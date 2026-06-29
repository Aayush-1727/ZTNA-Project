const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({

    service: "gmail",

    auth: {

        user: process.env.EMAIL_USER,

        pass: process.env.EMAIL_PASS

    }

});

async function sendOTP(email, otp) {

    await transporter.sendMail({

        from: process.env.EMAIL_USER,

        to: email,

        subject: "ZTNA Login OTP",

        html: `
            <h2>Zero Trust Network Access (ZTNA)</h2>

            <p>Your One-Time Password (OTP) is:</p>

            <h1>${otp}</h1>

            <p>This OTP is valid for <b>5 minutes</b>.</p>

            <p>If you did not request this login, please ignore this email.</p>
        `

    });

}

module.exports = sendOTP;