'use strict';


/**
 * @namespace Account
 */

var server = require('server');
server.extend(module.superModule);
var csrfProtection = require('*/cartridge/scripts/middleware/csrf');
var userLoggedIn = require('*/cartridge/scripts/middleware/userLoggedIn');
var consentTracking = require('*/cartridge/scripts/middleware/consentTracking');

/**
 * Checks if the email value entered is correct format
 * @param {string} email - email string to check if valid
 * @returns {boolean} Whether email is valid
 */
function validateEmail(email) {
    var regex = /^[\w.%+-]+@[\w.-]+\.[\w]{2,6}$/;
    return regex.test(email);
}
/**
 * Account-Login : The Account-Login endpoint will render the shopper's account page. Once a shopper logs in they will see is a dashboard that displays profile, address, payment and order information.
 * @name Base/Account-Login
 * @function
 * @memberof Account
 * @param {middleware} - server.middleware.https
 * @param {middleware} - csrfProtection.validateAjaxRequest
 * @param {querystringparameter} - rurl - redirect url. The value of this is a number. This number then gets mapped to an endpoint set up in oAuthRenentryRedirectEndpoints.js
 * @param {httpparameter} - loginEmail - The email associated with the shopper's account.
 * @param {httpparameter} - loginPassword - The shopper's password
 * @param {httpparameter} - loginRememberMe - Whether or not the customer has decided to utilize the remember me feature.
 * @param {httpparameter} - csrf_token - a CSRF token
 * @param {category} - sensitive
 * @param {returns} - json
 * @param {serverfunction} - post
 *
 */
 server.replace(
    'Login',
    server.middleware.https,
    csrfProtection.validateAjaxRequest,
    function (req, res, next) {
        var CustomerMgr = require('dw/customer/CustomerMgr');
        var Resource = require('dw/web/Resource');
        var Site = require('dw/system/Site');

        var accountHelpers = require('*/cartridge/scripts/helpers/accountHelpers');
        var emailHelpers = require('*/cartridge/scripts/helpers/emailHelpers');
        var hooksHelper = require('*/cartridge/scripts/helpers/hooks');

        var email = req.form.loginEmail;
        var password = req.form.loginPassword;
        var rememberMe = req.form.loginRememberMe
            ? (!!req.form.loginRememberMe)
            : false;

        var customerLoginResult = accountHelpers.loginCustomer(email, password, rememberMe);

        if (customerLoginResult.error) {
            if (customerLoginResult.status === 'ERROR_CUSTOMER_LOCKED') {
                var context = {
                    customer: CustomerMgr.getCustomerByLogin(email) || null
                };

                var emailObj = {
                    to: email,
                    subject: Resource.msg('subject.account.locked.email', 'login', null),
                    from: Site.current.getCustomPreferenceValue('customerServiceEmail') || 'no-reply@testorganization.com',
                    type: emailHelpers.emailTypes.accountLocked
                };

                hooksHelper('app.customer.email', 'sendEmail', [emailObj, 'account/accountLockedEmail', context], function () {});
            }
            else if(customerLoginResult.status === 'ERROR_CUSTOMER_NOT_FOUND'){
                res.json({
                    error: ["Email ID not Registered"]
                });
            }
            else{
                res.json({
                    error: ["Incorrect Password"]
                });
            }
           

            return next();
        }

        if (customerLoginResult.authenticatedCustomer) {
            res.setViewData({ authenticatedCustomer: customerLoginResult.authenticatedCustomer });
            res.json({
                success: true,
                redirectUrl: accountHelpers.getLoginRedirectURL(req.querystring.rurl, req.session.privacyCache, false)
            });

            req.session.privacyCache.set('args', null);
        } else {
            res.json({ error: [Resource.msg('error.message.login.form', 'login', null)] });
        }

        return next();
    }
);

/**
 * Account-SubmitRegistration : The Account-SubmitRegistration endpoint is the endpoint that gets hit when a shopper submits their registration for a new account
 * @name Base/Account-SubmitRegistration
 * @function
 * @memberof Account
 * @param {middleware} - server.middleware.https
 * @param {middleware} - csrfProtection.validateAjaxRequest
 * @param {querystringparameter} - rurl - redirect url. The value of this is a number. This number then gets mapped to an endpoint set up in oAuthRenentryRedirectEndpoints.js
 * @param {httpparameter} - dwfrm_profile_customer_firstname - Input field for the shoppers's first name
 * @param {httpparameter} - dwfrm_profile_customer_lastname - Input field for the shopper's last name
 * @param {httpparameter} - dwfrm_profile_customer_phone - Input field for the shopper's phone number
 * @param {httpparameter} - dwfrm_profile_customer_email - Input field for the shopper's email address
 * @param {httpparameter} - dwfrm_profile_customer_emailconfirm - Input field for the shopper's email address
 * @param {httpparameter} - dwfrm_profile_login_password - Input field for the shopper's password
 * @param {httpparameter} - dwfrm_profile_login_passwordconfirm: - Input field for the shopper's password to confirm
 * @param {httpparameter} - dwfrm_profile_customer_addtoemaillist - Checkbox for whether or not a shopper wants to be added to the mailing list
 * @param {httpparameter} - csrf_token - hidden input field CSRF token
 * @param {category} - sensitive
 * @param {returns} - json
 * @param {serverfunction} - post
 */
server.replace(
    'SubmitRegistration',
    server.middleware.https,
    csrfProtection.validateAjaxRequest,
    function (req, res, next) {
        var CustomerMgr = require('dw/customer/CustomerMgr');
        var Resource = require('dw/web/Resource');

        var formErrors = require('*/cartridge/scripts/formErrors');

        var registrationForm = server.forms.getForm('profile');

        // form validation
        // if (registrationForm.customer.email.value.toLowerCase()
        //     !== registrationForm.customer.emailconfirm.value.toLowerCase()
        // ) {
        //     registrationForm.customer.email.valid = false;
        //     registrationForm.customer.emailconfirm.valid = false;
        //     registrationForm.customer.emailconfirm.error =
        //         Resource.msg('error.message.mismatch.email', 'forms', null);
        //     registrationForm.valid = false;
        // }

        if (registrationForm.login.password.value
            !== registrationForm.login.passwordconfirm.value
        ) {
            registrationForm.login.password.valid = false;
            registrationForm.login.passwordconfirm.valid = false;
            registrationForm.login.passwordconfirm.error =
                Resource.msg('error.message.mismatch.password', 'forms', null);
            registrationForm.valid = false;
        }

        if (!CustomerMgr.isAcceptablePassword(registrationForm.login.password.value)) {
            registrationForm.login.password.valid = false;
            registrationForm.login.passwordconfirm.valid = false;
            registrationForm.login.passwordconfirm.error =
                Resource.msg('error.message.password.constraints.not.matched', 'forms', null);
            registrationForm.valid = false;
        }

        // setting variables for the BeforeComplete function
        var registrationFormObj = {
            firstName: registrationForm.customer.firstname.value,
            lastName: registrationForm.customer.lastname.value,
            phone: registrationForm.customer.phone.value,
            email: registrationForm.customer.email.value,
           // emailConfirm: registrationForm.customer.emailconfirm.value,
            password: registrationForm.login.password.value,
            passwordConfirm: registrationForm.login.passwordconfirm.value,
            validForm: registrationForm.valid,
            form: registrationForm
        };

        if (registrationForm.valid) {
            res.setViewData(registrationFormObj);

            this.on('route:BeforeComplete', function (req, res) { // eslint-disable-line no-shadow
                var Transaction = require('dw/system/Transaction');
                var accountHelpers = require('*/cartridge/scripts/helpers/accountHelpers');
                var authenticatedCustomer;
                var serverError;

                // getting variables for the BeforeComplete function
                var registrationForm = res.getViewData(); // eslint-disable-line

                if (registrationForm.validForm) {
                    var login = registrationForm.email;
                    var password = registrationForm.password;

                    // attempt to create a new user and log that user in.
                    try {
                        Transaction.wrap(function () {
                            var error = {};
                            var newCustomer = CustomerMgr.createCustomer(login, password);

                            var authenticateCustomerResult = CustomerMgr.authenticateCustomer(login, password);
                            if (authenticateCustomerResult.status !== 'AUTH_OK') {
                                error = { authError: true, status: authenticateCustomerResult.status };
                                throw error;
                            }

                            authenticatedCustomer = CustomerMgr.loginCustomer(authenticateCustomerResult, false);

                            if (!authenticatedCustomer) {
                                error = { authError: true, status: authenticateCustomerResult.status };
                                throw error;
                            } else {
                                // assign values to the profile
                                var newCustomerProfile = newCustomer.getProfile();

                                newCustomerProfile.firstName = registrationForm.firstName;
                                newCustomerProfile.lastName = registrationForm.lastName;
                                newCustomerProfile.phoneHome = registrationForm.phone;
                                newCustomerProfile.email = registrationForm.email;
                            }
                        });
                    } catch (e) {
                        if (e.authError) {
                            serverError = true;
                        } else {
                            registrationForm.validForm = false;
                            registrationForm.form.customer.email.valid = false;
                            //registrationForm.form.customer.emailconfirm.valid = false;
                            registrationForm.form.customer.email.error =
                                Resource.msg('error.message.username.invalid', 'forms', null);
                        }
                    }
                }

                delete registrationForm.password;
                delete registrationForm.passwordConfirm;
                formErrors.removeFormValues(registrationForm.form);

                if (serverError) {
                    res.setStatusCode(500);
                    res.json({
                        success: false,
                        errorMessage: Resource.msg('error.message.unable.to.create.account', 'login', null)
                    });

                    return;
                }

                if (registrationForm.validForm) {
                    // send a registration email
                    accountHelpers.sendCreateAccountEmail(authenticatedCustomer.profile);

                    res.setViewData({ authenticatedCustomer: authenticatedCustomer });
                    res.json({
                        success: true,
                        redirectUrl: accountHelpers.getLoginRedirectURL(req.querystring.rurl, req.session.privacyCache, true)
                    });

                    req.session.privacyCache.set('args', null);
                } else {
                    res.json({
                        fields: formErrors.getFormErrors(registrationForm)
                    });
                }
            });
        } else {
            res.json({
                fields: formErrors.getFormErrors(registrationForm)
            });
        }

        return next();
    }
);



/**
 * Account-PasswordResetDialogForm : The Account-PasswordResetDialogForm endpoint is the endpoint that gets hit once the shopper has clicked forgot password and has submitted their email address to request to reset their password
 * @name Base/Account-PasswordResetDialogForm
 * @function
 * @memberof Account
 * @param {middleware} - server.middleware.https
 * @param {querystringparameter} - mobile - a flag determining whether or not the shopper is on a mobile sized screen
 * @param {httpparameter} - loginEmail - Input field, the shopper's email address
 * @param {category} - sensitive
 * @param {returns} - json
 * @param {serverfunction} - post
 */
server.replace('PasswordResetDialogForm', server.middleware.https, function (req, res, next) {
    var CustomerMgr = require('dw/customer/CustomerMgr');
    var Resource = require('dw/web/Resource');
    var URLUtils = require('dw/web/URLUtils');
    var accountHelpers = require('*/cartridge/scripts/helpers/accountHelpers');

    var email = req.form.loginEmail;
    var errorMsg;
    var isValid;
    var resettingCustomer;
    var mobile = req.querystring.mobile;
    var receivedMsgHeading = Resource.msg('label.resetpasswordreceived', 'login', null);
    var receivedMsgBody = Resource.msg('msg.requestedpasswordreset', 'login', null);
    var buttonText = Resource.msg('button.text.loginform', 'login', null);
    var returnUrl = URLUtils.url('Login-Show').toString();
    if (email) {
        isValid = validateEmail(email);
        if (isValid) {
            resettingCustomer = CustomerMgr.getCustomerByLogin(email);
            if (resettingCustomer) {
                accountHelpers.sendPasswordResetEmail(email, resettingCustomer);
            }
            var ttt= req.form.resend;
            res.render('/account/password/resetPasswordSend',{email:email,resend:req.form.resend});
            // res.json({
            //     success: true,
            //     receivedMsgHeading: receivedMsgHeading,
            //     receivedMsgBody: receivedMsgBody,
            //     buttonText: buttonText,
            //     mobile: mobile === 'true',
            //     returnUrl: returnUrl
            // });
        } else {
            errorMsg = Resource.msg('error.message.passwordreset', 'login', null);
            res.json({
                fields: {
                    loginEmail: errorMsg
                }
            });
        }
    } else {
        errorMsg = Resource.msg('error.message.required', 'login', null);
        res.json({
            fields: {
                loginEmail: errorMsg
            }
        });
    }
    next();
});



// /**
//  * Account-SetNewPassword : The Account-SetNewPassword endpoint renders the page that displays the password reset form
//  * @name Base/Account-SetNewPassword
//  * @function
//  * @memberof Account
//  * @param {middleware} - server.middleware.https
//  * @param {middleware} - consentTracking.consent
//  * @param {querystringparameter} - Token - SFRA utilizes this token to retrieve the shopper
//  * @param {category} - sensitive
//  * @param {renders} - isml
//  * @param {serverfunction} - get
//  */
// server.get('SetNewPassword', server.middleware.https, consentTracking.consent, function (req, res, next) {
//     var CustomerMgr = require('dw/customer/CustomerMgr');
//     var URLUtils = require('dw/web/URLUtils');

//     var passwordForm = server.forms.getForm('newPasswords');
//     passwordForm.clear();
//     var token = req.querystring.Token;
//     var resettingCustomer = CustomerMgr.getCustomerByToken(token);
//     if (!resettingCustomer) {
//         res.redirect(URLUtils.url('Account-PasswordReset'));
//     } else {
//         res.render('account/password/newPassword', { passwordForm: passwordForm, token: token });
//     }
//     next();
// });

// /**
//  * Account-SaveNewPassword : The Account-SaveNewPassword endpoint handles resetting a shoppers password. This is the last step in the forgot password user flow. (This step does not log the shopper in.)
//  * @name Base/Account-SaveNewPassword
//  * @function
//  * @memberof Account
//  * @param {middleware} - server.middleware.https
//  * @param {querystringparameter} - Token - SFRA utilizes this token to retrieve the shopper
//  * @param {httpparameter} - dwfrm_newPasswords_newpassword - Input field for the shopper's new password
//  * @param {httpparameter} - dwfrm_newPasswords_newpasswordconfirm  - Input field to confirm the shopper's new password
//  * @param {httpparameter} - save - unutilized param
//  * @param {category} - sensitive
//  * @param {renders} - isml
//  * @param {serverfunction} - post
//  */
// server.post('SaveNewPassword', server.middleware.https, function (req, res, next) {
//     var Transaction = require('dw/system/Transaction');
//     var Resource = require('dw/web/Resource');

//     var passwordForm = server.forms.getForm('newPasswords');
//     var token = req.querystring.Token;

//     if (passwordForm.newpassword.value !== passwordForm.newpasswordconfirm.value) {
//         passwordForm.valid = false;
//         passwordForm.newpassword.valid = false;
//         passwordForm.newpasswordconfirm.valid = false;
//         passwordForm.newpasswordconfirm.error =
//             Resource.msg('error.message.mismatch.newpassword', 'forms', null);
//     }

//     if (passwordForm.valid) {
//         var result = {
//             newPassword: passwordForm.newpassword.value,
//             newPasswordConfirm: passwordForm.newpasswordconfirm.value,
//             token: token,
//             passwordForm: passwordForm
//         };
//         res.setViewData(result);
//         this.on('route:BeforeComplete', function (req, res) { // eslint-disable-line no-shadow
//             var CustomerMgr = require('dw/customer/CustomerMgr');
//             var URLUtils = require('dw/web/URLUtils');
//             var Site = require('dw/system/Site');
//             var emailHelpers = require('*/cartridge/scripts/helpers/emailHelpers');

//             var formInfo = res.getViewData();
//             var status;
//             var resettingCustomer;
//             Transaction.wrap(function () {
//                 resettingCustomer = CustomerMgr.getCustomerByToken(formInfo.token);
//                 status = resettingCustomer.profile.credentials.setPasswordWithToken(
//                     formInfo.token,
//                     formInfo.newPassword
//                 );
//             });
//             if (status.error) {
//                 passwordForm.newpassword.valid = false;
//                 passwordForm.newpasswordconfirm.valid = false;
//                 passwordForm.newpasswordconfirm.error =
//                     Resource.msg('error.message.resetpassword.invalidformentry', 'forms', null);
//                 res.render('account/password/newPassword', {
//                     passwordForm: passwordForm,
//                     token: token
//                 });
//             } else {
//                 var email = resettingCustomer.profile.email;
//                 var url = URLUtils.https('Login-Show');
//                 var objectForEmail = {
//                     firstName: resettingCustomer.profile.firstName,
//                     lastName: resettingCustomer.profile.lastName,
//                     url: url
//                 };

//                 var emailObj = {
//                     to: email,
//                     subject: Resource.msg('subject.profile.resetpassword.email', 'login', null),
//                     from: Site.current.getCustomPreferenceValue('customerServiceEmail') || 'no-reply@testorganization.com',
//                     type: emailHelpers.emailTypes.passwordReset
//                 };

//                 emailHelpers.sendEmail(emailObj, 'account/password/passwordChangedEmail', objectForEmail);
//                 res.redirect(URLUtils.url('Login-Show'));
//             }
//         });
//     } else {
//         res.render('account/password/newPassword', { passwordForm: passwordForm, token: token });
//     }
//     next();
// });



module.exports = server.exports();
