const nodemailer = require('nodemailer');
const logger = require('./logger');
const { 
    EMAIL_HOST, 
    EMAIL_PORT, 
    EMAIL_USER, 
    EMAIL_PASS, 
    EMAIL_FROM,
    FRONTEND_URL 
} = require('../config/keys');

class MailerUtils {
    constructor() {
        this.transporter = null;
        this.initializeTransporter();
    }

    // Initialize email transporter
    async initializeTransporter() {
        try {
            this.transporter = nodemailer.createTransporter({
                host: EMAIL_HOST,
                port: EMAIL_PORT,
                secure: EMAIL_PORT == 465, // true for 465, false for other ports
                auth: {
                    user: EMAIL_USER,
                    pass: EMAIL_PASS,
                },
                tls: {
                    rejectUnauthorized: false
                }
            });

            // Verify connection configuration
            await this.transporter.verify();
            logger.info('Email transporter initialized successfully');
        } catch (error) {
            logger.error('Email transporter initialization failed:', error);
        }
    }

    // Send email
    async sendEmail(to, subject, html, text = null) {
        if (!this.transporter) {
            throw new Error('Email transporter not initialized');
        }

        try {
            const mailOptions = {
                from: EMAIL_FROM,
                to,
                subject,
                html,
                text: text || this.stripHtml(html)
            };

            const result = await this.transporter.sendMail(mailOptions);
            logger.info(`Email sent successfully to ${to}`, {
                messageId: result.messageId,
                subject
            });

            return result;
        } catch (error) {
            logger.error(`Failed to send email to ${to}:`, error);
            throw error;
        }
    }

    // Send password reset email
    async sendPasswordResetEmail(email, resetToken, firstName) {
        const resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
        
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Reset - Hostel Management</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #007bff; color: white; padding: 20px; text-align: center; }
                .content { background: #f9f9f9; padding: 30px; }
                .button { 
                    display: inline-block; 
                    background: #007bff; 
                    color: white; 
                    padding: 12px 30px; 
                    text-decoration: none; 
                    border-radius: 5px; 
                    margin: 20px 0; 
                }
                .footer { background: #333; color: white; padding: 20px; text-align: center; font-size: 12px; }
                .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🏠 Hostel Management System</h1>
                    <p>Password Reset Request</p>
                </div>
                
                <div class="content">
                    <h2>Hello ${firstName}!</h2>
                    
                    <p>We received a request to reset your password for your Hostel Management System account. If you made this request, click the button below to reset your password:</p>
                    
                    <div style="text-align: center;">
                        <a href="${resetUrl}" class="button">Reset Your Password</a>
                    </div>
                    
                    <p>Or copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 3px;">${resetUrl}</p>
                    
                    <div class="warning">
                        <strong>⚠️ Important Security Information:</strong>
                        <ul>
                            <li>This link will expire in <strong>10 minutes</strong> for security reasons</li>
                            <li>If you didn't request this password reset, please ignore this email</li>
                            <li>Never share this link with anyone else</li>
                            <li>If you're concerned about your account security, contact the system administrator immediately</li>
                        </ul>
                    </div>
                    
                    <p>If you're having trouble clicking the button, you can also log in to the system and use the "Forgot Password" feature.</p>
                    
                    <p>Best regards,<br>
                    Hostel Management Team</p>
                </div>
                
                <div class="footer">
                    <p>This is an automated email from the Hostel Management System.</p>
                    <p>If you need help, please contact your system administrator.</p>
                    <p>&copy; ${new Date().getFullYear()} Hostel Management System. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        `;

        const subject = 'Password Reset Request - Hostel Management System';
        
        return await this.sendEmail(email, subject, html);
    }

    // Send welcome email to new users
    async sendWelcomeEmail(email, firstName, studentId, tempPassword) {
        const loginUrl = `${FRONTEND_URL}/login`;
        
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Welcome - Hostel Management</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #28a745; color: white; padding: 20px; text-align: center; }
                .content { background: #f9f9f9; padding: 30px; }
                .credentials { background: #e9ecef; padding: 20px; border-radius: 5px; margin: 20px 0; }
                .button { 
                    display: inline-block; 
                    background: #28a745; 
                    color: white; 
                    padding: 12px 30px; 
                    text-decoration: none; 
                    border-radius: 5px; 
                    margin: 20px 0; 
                }
                .footer { background: #333; color: white; padding: 20px; text-align: center; font-size: 12px; }
                .warning { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🏠 Welcome to Hostel Management System</h1>
                    <p>Your account has been created!</p>
                </div>
                
                <div class="content">
                    <h2>Hello ${firstName}!</h2>
                    
                    <p>Welcome to the Hostel Management System! Your account has been successfully created. You can now access the system to manage your hostel-related activities.</p>
                    
                    <div class="credentials">
                        <h3>🔑 Your Login Credentials:</h3>
                        <p><strong>Student ID:</strong> ${studentId}</p>
                        <p><strong>Temporary Password:</strong> ${tempPassword}</p>
                    </div>
                    
                    <div class="warning">
                        <strong>🔒 Important Security Notice:</strong>
                        <p>This is a temporary password. For your security, you <strong>must change your password</strong> after your first login.</p>
                    </div>
                    
                    <div style="text-align: center;">
                        <a href="${loginUrl}" class="button">Login to Your Account</a>
                    </div>
                    
                    <h3>📱 What you can do with the system:</h3>
                    <ul>
                        <li>View and update your profile information</li>
                        <li>Check your attendance records</li>
                        <li>Submit and track complaints</li>
                        <li>Receive important hostel notices</li>
                        <li>View fee information and payment status</li>
                    </ul>
                    
                    <h3>🆘 Need Help?</h3>
                    <p>If you have any questions or need assistance:</p>
                    <ul>
                        <li>Contact your hostel warden</li>
                        <li>Visit the hostel office during office hours</li>
                        <li>Use the help section in the system</li>
                    </ul>
                    
                    <p>Best regards,<br>
                    Hostel Management Team</p>
                </div>
                
                <div class="footer">
                    <p>This is an automated email from the Hostel Management System.</p>
                    <p>&copy; ${new Date().getFullYear()} Hostel Management System. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        `;

        const subject = 'Welcome to Hostel Management System - Account Created';
        
        return await this.sendEmail(email, subject, html);
    }

    // Send account locked notification
    async sendAccountLockedEmail(email, firstName, studentId) {
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Account Security Alert</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
                .content { background: #f9f9f9; padding: 30px; }
                .footer { background: #333; color: white; padding: 20px; text-align: center; font-size: 12px; }
                .alert { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Security Alert</h1>
                    <p>Account Temporarily Locked</p>
                </div>
                
                <div class="content">
                    <h2>Hello ${firstName},</h2>
                    
                    <div class="alert">
                        <strong>⚠️ Your account (${studentId}) has been temporarily locked</strong>
                    </div>
                    
                    <p>Your account has been automatically locked due to multiple failed login attempts. This is a security measure to protect your account from unauthorized access.</p>
                    
                    <h3>📋 What happened:</h3>
                    <ul>
                        <li>Multiple unsuccessful login attempts were detected</li>
                        <li>Your account has been locked for 2 hours as a security precaution</li>
                        <li>The lock will be automatically removed after the timeout period</li>
                    </ul>
                    
                    <h3>🔧 What you can do:</h3>
                    <ul>
                        <li>Wait for 2 hours and then try logging in again</li>
                        <li>If you forgot your password, use the "Forgot Password" feature</li>
                        <li>If you didn't attempt to login, contact the system administrator immediately</li>
                        <li>Ensure you're using the correct Student ID and password</li>
                    </ul>
                    
                    <h3>🛡️ Security Tips:</h3>
                    <ul>
                        <li>Never share your login credentials with anyone</li>
                        <li>Use a strong, unique password</li>
                        <li>Always log out when using shared computers</li>
                        <li>Report any suspicious activity immediately</li>
                    </ul>
                    
                    <p>If you believe this is an error or if you need immediate assistance, please contact your hostel warden or system administrator.</p>
                    
                    <p>Best regards,<br>
                    Hostel Management Security Team</p>
                </div>
                
                <div class="footer">
                    <p>This is an automated security notification from the Hostel Management System.</p>
                    <p>Time: ${new Date().toLocaleString()}</p>
                </div>
            </div>
        </body>
        </html>
        `;

        const subject = 'Security Alert: Account Temporarily Locked - Hostel Management System';
        
        return await this.sendEmail(email, subject, html);
    }

    // Send password changed notification
    async sendPasswordChangeNotification(email, firstName, studentId) {
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Changed Successfully</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #28a745; color: white; padding: 20px; text-align: center; }
                .content { background: #f9f9f9; padding: 30px; }
                .footer { background: #333; color: white; padding: 20px; text-align: center; font-size: 12px; }
                .success { background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Password Updated</h1>
                    <p>Security Confirmation</p>
                </div>
                
                <div class="content">
                    <h2>Hello ${firstName},</h2>
                    
                    <div class="success">
                        <strong>✅ Your password has been successfully changed</strong>
                    </div>
                    
                    <p>This email confirms that the password for your account (${studentId}) was changed successfully on ${new Date().toLocaleString()}.</p>
                    
                    <h3>🔒 Security Information:</h3>
                    <ul>
                        <li>Your account is now secured with your new password</li>
                        <li>Any existing login sessions have been invalidated</li>
                        <li>You'll need to use your new password for future logins</li>
                    </ul>
                    
                    <h3>⚠️ If you didn't make this change:</h3>
                    <p>If you did not request or make this password change, your account may have been compromised. Please:</p>
                    <ul>
                        <li>Contact the system administrator immediately</li>
                        <li>Reset your password using the "Forgot Password" feature</li>
                        <li>Review your account activity</li>
                    </ul>
                    
                    <p>Thank you for keeping your account secure!</p>
                    
                    <p>Best regards,<br>
                    Hostel Management Security Team</p>
                </div>
                
                <div class="footer">
                    <p>This is an automated security notification from the Hostel Management System.</p>
                    <p>Time: ${new Date().toLocaleString()}</p>
                </div>
            </div>
        </body>
        </html>
        `;

        const subject = 'Password Changed Successfully - Hostel Management System';
        
        return await this.sendEmail(email, subject, html);
    }

    // Send system maintenance notification
    async sendMaintenanceNotification(email, firstName, maintenanceInfo) {
        const { startTime, endTime, description, affectedServices } = maintenanceInfo;
        
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>System Maintenance Notification</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #ffc107; color: #333; padding: 20px; text-align: center; }
                .content { background: #f9f9f9; padding: 30px; }
                .footer { background: #333; color: white; padding: 20px; text-align: center; font-size: 12px; }
                .info { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔧 System Maintenance</h1>
                    <p>Scheduled Maintenance Notification</p>
                </div>
                
                <div class="content">
                    <h2>Hello ${firstName},</h2>
                    
                    <p>We want to inform you about scheduled maintenance for the Hostel Management System.</p>
                    
                    <div class="info">
                        <h3>📅 Maintenance Schedule:</h3>
                        <p><strong>Start:</strong> ${new Date(startTime).toLocaleString()}</p>
                        <p><strong>End:</strong> ${new Date(endTime).toLocaleString()}</p>
                        <p><strong>Duration:</strong> ${Math.ceil((new Date(endTime) - new Date(startTime)) / (1000 * 60 * 60))} hours (estimated)</p>
                    </div>
                    
                    <h3>🔧 What's being updated:</h3>
                    <p>${description}</p>
                    
                    <h3>🚫 Affected Services:</h3>
                    <ul>
                        ${affectedServices.map(service => `<li>${service}</li>`).join('')}
                    </ul>
                    
                    <h3>💡 What you need to know:</h3>
                    <ul>
                        <li>The system will be unavailable during this time</li>
                        <li>Please save any work before the maintenance window</li>
                        <li>We'll send another email when maintenance is complete</li>
                        <li>Emergency contact information will remain available</li>
                    </ul>
                    
                    <p>We apologize for any inconvenience and appreciate your patience as we improve the system.</p>
                    
                    <p>Best regards,<br>
                    Hostel Management Technical Team</p>
                </div>
                
                <div class="footer">
                    <p>This is an automated notification from the Hostel Management System.</p>
                </div>
            </div>
        </body>
        </html>
        `;

        const subject = 'Scheduled System Maintenance - Hostel Management System';
        
        return await this.sendEmail(email, subject, html);
    }

    // Utility function to strip HTML tags from text
    stripHtml(html) {
        return html.replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').trim();
    }

    // Send bulk emails
    async sendBulkEmails(recipients, subject, html, batchSize = 10) {
        const results = [];
        
        // Process in batches to avoid overwhelming the email service
        for (let i = 0; i < recipients.length; i += batchSize) {
            const batch = recipients.slice(i, i + batchSize);
            const batchPromises = batch.map(async (recipient) => {
                try {
                    const result = await this.sendEmail(recipient.email, subject, html);
                    return { email: recipient.email, success: true, result };
                } catch (error) {
                    logger.error(`Failed to send bulk email to ${recipient.email}:`, error);
                    return { email: recipient.email, success: false, error: error.message };
                }
            });

            const batchResults = await Promise.allSettled(batchPromises);
            results.push(...batchResults.map(r => r.value || { success: false, error: 'Unknown error' }));

            // Wait a bit between batches to be respectful to the email service
            if (i + batchSize < recipients.length) {
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }

        return results;
    }

    // Test email configuration
    async testEmailConfig() {
        try {
            await this.transporter.verify();
            logger.info('Email configuration test successful');
            return { success: true, message: 'Email configuration is working' };
        } catch (error) {
            logger.error('Email configuration test failed:', error);
            return { success: false, error: error.message };
        }
    }
}

module.exports = new MailerUtils();