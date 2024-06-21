const sgMail = require("@sendgrid/mail");
require("dotenv").config();

async function sendEmailWithSendGrid(email, token, num) {
  sgMail.setApiKey(process.env.TOKEN_SENDGRID);

  const verificationLink = `localhost:3000/api/users/verify/${token}`;

  const msg = {
    to: email,
    from: {
      email: process.env.MY_EMAIL,
      name: "ContactsApp",
    },
    subject: "Hello from ContactsApp!",
    text: `Hello from ContactsApp\n\nClick the link to validate your account:\n\n${verificationLink}\n\nOr insert this link in the URL: ${verificationLink}`,
    html: `Hello from <strong>ContactsApp</strong>! <br />
      <a href="${verificationLink}">Click here</a> to validate your account. <br />
      Or insert this link in the URL: ${verificationLink}`,
  };

  if (num === 2) {
    msg.subject = "Verification email resent";
  }

  try {
    await sgMail.send(msg);
    console.log(`Email sent successfully to ${email} from ${msg.from.email}`);
  } catch (error) {
    if (error?.response) {
      console.error(error?.response.body);
    } else {
      console.error(error);
    }
  }
}

module.exports = sendEmailWithSendGrid;
