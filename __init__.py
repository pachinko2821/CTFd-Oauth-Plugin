import os
from flask import redirect, render_template, request, session, url_for
from flask_babel import lazy_gettext as _l

from werkzeug.routing import Rule
from werkzeug.middleware.proxy_fix import ProxyFix
from google_auth_oauthlib.flow import Flow
from pathlib import Path
import requests

from CTFd.models import Brackets, UserFieldEntries, UserFields, Users, db
from CTFd.api.v1.users import UserPrivate
from CTFd.utils import config, email, get_config
from CTFd.utils import validators
from CTFd.utils.config import is_teams_mode
from CTFd.utils.helpers import get_errors
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user
from CTFd.utils.validators import ValidationError
from CTFd.utils.plugins import override_template
from CTFd.utils.user import get_current_user
from CTFd.schemas.users import UserSchema
from CTFd.utils.security.auth import update_user
from CTFd.cache import clear_challenges, clear_standings


class FakeRequest():
    def __init__(self, form, args):
        self.form = form
        self.args = args

def load(app):
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1, 
        x_proto=1, 
        x_host=1, 
        x_port=1
    )

    GOOGLE_SCOPES = [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ]

    REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8000/register")

    dir_path = Path(__file__).parent.resolve()
    client_secrets = dir_path / "client_secrets.json"
    flow = Flow.from_client_secrets_file(
        client_secrets,
        GOOGLE_SCOPES,
        redirect_uri=REDIRECT_URI
    )

    def original_register(request):
        errors = get_errors()

        pre_existing_user = False

        name = request.form.get("name", "").strip()
        email_address = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        website = request.form.get("website")
        affiliation = request.form.get("affiliation")
        country = request.form.get("country")
        registration_code = str(request.form.get("registration_code", ""))
        bracket_id = request.form.get("bracket_id", None)

        name_len = len(name) == 0
        emails = (
            Users.query.add_columns(Users.email, Users.id)
            .filter_by(email=email_address)
            .first()
        )
        pass_short = len(password) == 0
        pass_long = len(password) > 128
        valid_email = validators.validate_email(email_address)
        team_name_email_check = validators.validate_email(name)

        password_min_length = 10
        pass_min = len(password) < password_min_length

        if get_config("registration_code"):
            if (
                registration_code.lower()
                != str(get_config("registration_code", default="")).lower()
            ):
                errors.append(_l("The registration code you entered was incorrect"))

        # Process additional user fields
        fields = {}
        for field in UserFields.query.all():
            fields[field.id] = field

        entries = {}
        for field_id, field in fields.items():
            value = request.form.get(f"fields[{field_id}]", "").strip()
            if field.required is True and (value is None or value == ""):
                errors.append(_l("Please provide all required fields"))
                break

            if field.field_type == "boolean":
                entries[field_id] = bool(value)
            else:
                entries[field_id] = value

        if country:
            try:
                validators.validate_country_code(country)
                valid_country = True
            except ValidationError:
                valid_country = False
        else:
            valid_country = True

        if website:
            valid_website = validators.validate_url(website)
        else:
            valid_website = True

        if affiliation:
            valid_affiliation = len(affiliation) < 128
        else:
            valid_affiliation = True

        if bracket_id:
            valid_bracket = bool(
                Brackets.query.filter_by(id=bracket_id, type="users").first()
            )
        else:
            if Brackets.query.filter_by(type="users").count():
                valid_bracket = False
            else:
                valid_bracket = True

        if not valid_email:
            errors.append(_l("Please enter a valid email address"))
        if email.check_email_is_whitelisted(email_address) is False:
            errors.append(_l("Your email address is not from an allowed domain"))
        if email.check_email_is_blacklisted(email_address) is True:
            errors.append(_l("Your email address is not from an allowed domain"))
        if team_name_email_check is True:
            errors.append(_l("Your user name cannot be an email address"))
        if emails:
            pre_existing_user = True
        if pass_short:
            errors.append(_l("Pick a longer password"))
        if password_min_length and pass_min:
            errors.append(
                _l(f"Password must be at least {password_min_length} characters")
            )
        if pass_long:
            errors.append(_l("Pick a shorter password"))
        if name_len:
            errors.append(_l("Pick a longer user name"))
        if valid_website is False:
            errors.append(
                _l("Websites must be a proper URL starting with http or https")
            )
        if valid_country is False:
            errors.append(_l("Invalid country"))
        if valid_affiliation is False:
            errors.append(_l("Please provide a shorter affiliation"))
        if valid_bracket is False:
            errors.append(_l("Please provide a valid bracket"))

        if len(errors) > 0:
            return render_template(
                "register.html",
                errors=errors,
                name=request.form["name"],
                email=request.form["email"],
                password=request.form["password"],
            )
        else:
            with app.app_context():
                user = Users(
                    name=name,
                    email=email_address,
                    password=password,
                    bracket_id=bracket_id,
                )

                if website:
                    user.website = website
                if affiliation:
                    user.affiliation = affiliation
                if country:
                    user.country = country

                if not pre_existing_user:
                    db.session.add(user)
                    db.session.commit()
                    db.session.flush()

                    for field_id, value in entries.items():
                        entry = UserFieldEntries(
                            field_id=field_id, value=value, user_id=user.id
                        )
                        db.session.add(entry)
                    db.session.commit()
                else:
                    user = Users.query.filter_by(email=email_address).first()
                    login_user(user)

                if request.args.get("next") and validators.is_safe_url(
                    request.args.get("next")
                ):
                    return redirect(request.args.get("next"))

                if config.can_send_mail() and get_config(
                    "verify_emails"
                ):  # Confirming users is enabled and we can send email.
                    log(
                        "registrations",
                        format="[{date}] {ip} - {name} registered (UNCONFIRMED) with {email}",
                        name=user.name,
                        email=user.email,
                    )
                    email.verify_email_address(user.email)
                    db.session.close()
                    return redirect(url_for("auth.confirm"))
                else:  # Don't care about confirming users
                    if (
                        config.can_send_mail()
                    ):  # We want to notify the user that they have registered.
                        email.successful_registration_notification(user.email)

        log(
            "registrations",
            format="[{date}] {ip} - {name} registered with {email}",
            name=user.name,
            email=user.email,
        )
        db.session.close()

        if is_teams_mode():
            return redirect(url_for("teams.private"))

        return redirect(url_for("challenges.listing"))
        
    def get_user_details(token):
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.get("https://openidconnect.googleapis.com/v1/userinfo", timeout=10, headers=headers)
        return response.json()

    @app.route("/oauth/init", methods=["GET"])
    def oauth_init():
        authorization_url, state = flow.authorization_url(
            include_granted_scopes="true",
            access_type="offline",
            prompt="consent"
        )

        print("done")
        session["oauth_state"] = state
        return redirect(authorization_url)

    def register():
        if request.method == "GET":
            error = request.args.get("error", False)
            next = request.args.get("next", False)

            if error:
                return 403, "error"
            
            code = request.args.get("code", False)
            if not code:
                dir_path = Path(__file__).parent.resolve()
                template_path = dir_path / 'templates' / 'register_oauth.html'
                override_template('register.html', open(template_path).read())
                return render_template('register.html', google_oauth_url="/oauth/init")
            
            state = request.args.get("state", False)
            session_state = session["oauth_state"]

            if not state == session_state:
                return 403, "incorrect state" 
            
            # Get details from the token
            authorization_response = request.url
            flow.fetch_token(authorization_response=authorization_response)

            credentials = flow.credentials
            user = get_user_details(credentials.token)

            if not set(credentials.granted_scopes) == set(GOOGLE_SCOPES):
                return 403, "not all requested scopes were granted"

            # Register the user
            name = user.get("name", False)
            email_address = user.get("email", False)

            # generate a random password
            password = os.urandom(32).hex()

            # random details
            website = "https://phonepe.com"
            affiliation = "affiliation"
            country = "IN"

            fake_form = {
                "name": name,
                "email": email_address,
                "password": password,
                "website": website,
                "affiliation": affiliation,
                "country": country
            }

            fake_args = {
                "next": next
            }

            fake_request = FakeRequest(fake_form, fake_args)

            return original_register(fake_request)

    def patch_user(self):
        user = get_current_user()
        data = request.get_json()

        if not user.email:
            return {"success": False, "errors": response.errors}, 400
        
        if not user.email == data["email"]:
            data["email"] = user.email
            data["affiliation"] = "Bruh, no touch email"

        schema = UserSchema(view="self", instance=user, partial=True)
        response = schema.load(data)
        if response.errors:
            return {"success": False, "errors": response.errors}, 400

        db.session.commit()

        # Update user's session for the new session hash
        update_user(user)

        response = schema.dump(response.data)
        db.session.close()

        clear_standings()
        clear_challenges()

        return {"success": True, "data": response.data}

    # The format used by the view_functions dictionary is blueprint.view_function_name
    app.view_functions['auth.register'] = register
    UserPrivate.patch = patch_user

    # Add method to the register endpoint
    app.url_map.add(Rule("/register", endpoint="auth.register", methods=["GET", "POST"]))