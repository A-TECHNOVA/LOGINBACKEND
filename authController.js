const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { validationResult } = require('express-validator');

const User = require('../models/User');
const AccessLog = require('../models/AccessLog');
const { JWT_SECRET, JWT_EXPIRE } = require('../config/keys');
const logger = require('../utils/logger');
const { sendPasswordResetEmail } = require('../utils/mailer');

class AuthController {
    // Generate JWT Token
    generateToken(payload) {
        return jwt.sign(payload, JWT_SECRET, { 
            expiresIn: JWT_EXPIRE,
            issuer: 'hostel-management-system'
        });
    }

    // Extract request info for logging
    getRequestInfo(req) {
        return {
            ip: req.ip || req.connection.remoteAddress || 'unknown',
            userAgent: req.get('User-Agent') || 'unknown'
        };
    }

    // Login handler
    async login(req, res) {
        try {
            // Validate input
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const { studentId, password, role } = req.body;
            const requestInfo = this.getRequestInfo(req);

            // Find user by student ID
            const user = await User.findOne({ 
                studentId: studentId.toUpperCase(),
                'security.isActive': true 
            });

            if (!user) {
                // Log failed attempt
                await AccessLog.logAccess({
                    studentId: studentId.toUpperCase(),
                    action: 'LOGIN_FAILED',
                    result: 'FAILURE',
                    details: { reason: 'User not found' },
                    session: requestInfo
                });

                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }

            // Check if account is locked
            if (user.isLocked) {
                await AccessLog.logAccess({
                    userId: user._id,
                    studentId: user.studentId,
                    action: 'LOGIN_FAILED',
                    result: 'FAILURE',
                    details: { reason: 'Account locked' },
                    session: requestInfo
                });

                return res.status(423).json({
                    success: false,
                    message: 'Account is temporarily locked due to multiple failed login attempts'
                });
            }

            // Verify role matches
            if (role && user.role !== role) {
                await AccessLog.logAccess({
                    userId: user._id,
                    studentId: user.studentId,
                    action: 'LOGIN_FAILED',
                    result: 'FAILURE',
                    details: { reason: 'Role mismatch' },
                    session: requestInfo
                });

                return res.status(401).json({
                    success: false,
                    message: 'Invalid role for this user'
                });
            }

            // Compare password
            const isPasswordMatch = await user.comparePassword(password);
            if (!isPasswordMatch) {
                await AccessLog.logAccess({
                    userId: user._id,
                    studentId: user.studentId,
                    action: 'LOGIN_FAILED',
                    result: 'FAILURE',
                    details: { reason: 'Invalid password' },
                    session: requestInfo
                });

                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }

            // Update last login
            await user.updateLastLogin();

            // Generate JWT token
            const token = this.generateToken({
                userId: user._id,
                studentId: user.studentId,
                role: user.role
            });

            // Log successful login
            await AccessLog.logAccess({
                userId: user._id,
                studentId: user.studentId,
                action: 'LOGIN_SUCCESS',
                result: 'SUCCESS',
                session: requestInfo
            });

            // Log activity
            logger.info(`Successful login: ${user.studentId} (${user.role})`, {
                userId: user._id,
                ip: requestInfo.ip
            });

            res.json({
                success: true,
                message: 'Login successful',
                token,
                user: {
                    id: user._id,
                    studentId: user.studentId,
                    role: user.role,
                    profile: user.profile,
                    lastLogin: user.security.lastLogin
                }
            });

        } catch (error) {
            logger.error('Login error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Logout handler
    async logout(req, res) {
        try {
            const requestInfo = this.getRequestInfo(req);

            // Log logout
            await AccessLog.logAccess({
                userId: req.user.userId,
                studentId: req.user.studentId,
                action: 'LOGOUT',
                result: 'SUCCESS',
                session: requestInfo
            });

            logger.info(`User logged out: ${req.user.studentId}`, {
                userId: req.user.userId,
                ip: requestInfo.ip
            });

            res.json({
                success: true,
                message: 'Logged out successfully'
            });

        } catch (error) {
            logger.error('Logout error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Forgot password handler
    async forgotPassword(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const { studentId, email } = req.body;
            const requestInfo = this.getRequestInfo(req);

            // Find user by student ID and email
            const user = await User.findOne({
                studentId: studentId.toUpperCase(),
                'profile.email': email.toLowerCase(),
                'security.isActive': true
            });

            if (!user) {
                await AccessLog.logAccess({
                    studentId: studentId.toUpperCase(),
                    action: 'PASSWORD_RESET_REQUEST',
                    result: 'FAILURE',
                    details: { reason: 'User not found' },
                    session: requestInfo
                });

                // Return success message even if user not found (security)
                return res.json({
                    success: true,
                    message: 'If your account exists, you will receive a password reset email'
                });
            }

            // Generate reset token
            const resetToken = user.generatePasswordResetToken();
            await user.save();

            // Send reset email
            try {
                await sendPasswordResetEmail(user.profile.email, resetToken, user.profile.firstName);
                
                await AccessLog.logAccess({
                    userId: user._id,
                    studentId: user.studentId,
                    action: 'PASSWORD_RESET_REQUEST',
                    result: 'SUCCESS',
                    session: requestInfo
                });

                logger.info(`Password reset email sent: ${user.studentId}`, {
                    userId: user._id,
                    email: user.profile.email
                });

            } catch (emailError) {
                logger.error('Password reset email failed:', emailError);
                
                await AccessLog.logAccess({
                    userId: user._id,
                    studentId: user.studentId,
                    action: 'PASSWORD_RESET_REQUEST',
                    result: 'ERROR',
                    details: { reason: 'Email sending failed' },
                    session: requestInfo
                });
            }

            res.json({
                success: true,
                message: 'If your account exists, you will receive a password reset email'
            });

        } catch (error) {
            logger.error('Forgot password error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Reset password handler
    async resetPassword(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const { token, password } = req.body;
            const requestInfo = this.getRequestInfo(req);

            // Hash the token to match what's stored in database
            const hashedToken = crypto
                .createHash('sha256')
                .update(token)
                .digest('hex');

            // Find user with valid reset token
            const user = await User.findOne({
                'security.passwordResetToken': hashedToken,
                'security.passwordResetExpires': { $gt: Date.now() },
                'security.isActive': true
            });

            if (!user) {
                await AccessLog.logAccess({
                    studentId: 'UNKNOWN',
                    action: 'PASSWORD_RESET_SUCCESS',
                    result: 'FAILURE',
                    details: { reason: 'Invalid or expired reset token' },
                    session: requestInfo
                });

                return res.status(400).json({
                    success: false,
                    message: 'Password reset token is invalid or has expired'
                });
            }

            // Update password
            user.password = password;
            user.security.passwordResetToken = undefined;
            user.security.passwordResetExpires = undefined;
            user.security.loginAttempts = 0;
            user.security.lockUntil = undefined;

            await user.save();

            // Log successful password reset
            await AccessLog.logAccess({
                userId: user._id,
                studentId: user.studentId,
                action: 'PASSWORD_RESET_SUCCESS',
                result: 'SUCCESS',
                session: requestInfo
            });

            logger.info(`Password reset successful: ${user.studentId}`, {
                userId: user._id
            });

            res.json({
                success: true,
                message: 'Password has been reset successfully'
            });

        } catch (error) {
            logger.error('Reset password error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Verify token handler
    async verifyToken(req, res) {
        try {
            const user = await User.findById(req.user.userId)
                .select('-password -security.passwordResetToken');

            if (!user || !user.security.isActive) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid token'
                });
            }

            res.json({
                success: true,
                message: 'Token is valid',
                user: {
                    id: user._id,
                    studentId: user.studentId,
                    role: user.role,
                    profile: user.profile,
                    lastLogin: user.security.lastLogin
                }
            });

        } catch (error) {
            logger.error('Token verification error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }
}

module.exports = new AuthController();