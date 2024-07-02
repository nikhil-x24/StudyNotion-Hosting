const User = require("../models/User");
const mailSender = require("../utils/mailSender");
const bcrypt = require("bcrypt");

//resetPasswordtoken
exports.resetPasswordToken = async (req, res) => {
  try {
    //get email from req body:
    const email = req.body.email;

    //check user for this email, email validation:
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.json({
        success: false,
        message: "Your Email is not registered with us yet!",
      });
    }

    //generate token:
    const token = crypto.randomUUID();

    //update user by adding token & expiry time:
    const updatedDetails = await User.findOneAndUpdate(
      { email: email },
      {
        token: token,
        resetPasswordExpires: Date.now() + 5 * 60 * 1000,
      },
      { new: true }
    );

    //create URL:
    const url = `http://localhost:3000/update-password/${token}`;
    //send mail containing the url:
    await mailSender(
      email,
      "Password reset link",
      `Your Link for email verification is ${url}. Please click this url to reset your password.`
    );

    //return response:
    return res.json({
      success: true,
      message:
        "Email Sent Successfully, Please Check Your Email to Continue Further",
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      success: false,
      message: `Some Error in Sending the Reset Message`,
    });
  }
};

//resetPassword
exports.resetPassword = async (req, res) => {
  try {
    //fetch data
    const { password, confirmPassword, token } = req.body;

    //validation
    if (confirmPassword !== password) {
      return res.json({
        success: false,
        message: "Password and Confirm Password Does not Match",
      });
    }

    //get user details from db using token
    const userDetails = await User.findOne({ token: token });
    //if no entry, Invalid token:
    if (!userDetails) {
      return res.json({
        success: false,
        message: "Token is Invalid",
      });
    }

    //token time check
    if (!(userDetails.resetPasswordExpires > Date.now())) {
      return res.status(403).json({
        success: false,
        message: `Token is Expired, Please Regenerate Your Token`,
      });
    }

    //hash password
    const encryptedPassword = await bcrypt.hash(password, 10);
    //update password, return response
    await User.findOneAndUpdate(
      { token: token },
      { password: encryptedPassword },
      { new: true }
    );
    res.json({
      success: true,
      message: `Password Reset Successful`,
    });
  } catch (error) {
    return res.json({
      error: error.message,
      success: false,
      message: `Some Error in Updating the Password`,
    });
  }
};
