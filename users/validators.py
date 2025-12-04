
import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class PasswordValidator:
    
    
    def __init__(self, min_length=8, require_digit=True, require_uppercase=True, 
                 require_lowercase=True, require_special_char=False):
        self.min_length = min_length
        self.require_digit = require_digit
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_special_char = require_special_char
    
    def __call__(self, value):
        
        errors = []
        
        if len(value) < self.min_length:
            errors.append(_(f'Password must be at least {self.min_length} characters long.'))
        
        if self.require_digit and not re.search(r'\d', value):
            errors.append(_('Password must contain at least one digit (0-9).'))
        
        if self.require_uppercase and not re.search(r'[A-Z]', value):
            errors.append(_('Password must contain at least one uppercase letter (A-Z).'))
        
        if self.require_lowercase and not re.search(r'[a-z]', value):
            errors.append(_('Password must contain at least one lowercase letter (a-z).'))
        
        if self.require_special_char and not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            errors.append(_('Password must contain at least one special character.'))
        
        if errors:
            raise ValidationError(errors)


password_validator = PasswordValidator()


class EmailValidator:
    
    
    def __call__(self, value):
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', value):
            raise ValidationError(_('Enter a valid email address.'))


email_validator = EmailValidator()


def validate_name(value):
    if not re.match(r'^[A-Za-z\s\'-]+$', value):
        raise ValidationError(
            _('Name can only contain letters, spaces, hyphens, and apostrophes.')
        )
    
    if len(value) < 2:
        raise ValidationError(_('Name must be at least 2 characters long.'))
    
    if len(value) > 50:
        raise ValidationError(_('Name cannot exceed 50 characters.'))


def validate_phone_number(value):
    digits = re.sub(r'\D', '', value)
    
    if not (10 <= len(digits) <= 15):
        raise ValidationError(_('Phone number must be between 10 and 15 digits.'))
    
    if not re.match(r'^(\+|0|1)', value.replace(' ', '')):
        raise ValidationError(_('Phone number must start with +, 0, or 1.'))
    