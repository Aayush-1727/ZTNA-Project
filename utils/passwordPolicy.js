function validatePassword(password) {

    if (!password) {

        return {
            valid: false,
            message: "Password is required."
        };

    }

    if (password.length < 8) {

        return {
            valid: false,
            message: "Password must be at least 8 characters long."
        };

    }

    if (/\s/.test(password)) {

        return {
            valid: false,
            message: "Password cannot contain spaces."
        };

    }

    if (!/[A-Z]/.test(password)) {

        return {
            valid: false,
            message: "Password must contain at least one uppercase letter."
        };

    }

    if (!/[a-z]/.test(password)) {

        return {
            valid: false,
            message: "Password must contain at least one lowercase letter."
        };

    }

    if (!/[0-9]/.test(password)) {

        return {
            valid: false,
            message: "Password must contain at least one number."
        };

    }

    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {

        return {
            valid: false,
            message: "Password must contain at least one special character."
        };

    }

    return {

        valid: true,

        message: "Strong Password"

    };

}

module.exports = validatePassword;