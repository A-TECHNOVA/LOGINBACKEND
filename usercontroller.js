const { validationResult } = require('express-validator');
const User = require('../models/User');
const AccessLog = require('../models/AccessLog');
const logger = require('../utils/logger');

class UserController {
    // Get user profile
    async getProfile(req, res) {
        try {
            const user = await User.findById(req.user.userId)
                .select('-password -security.passwordResetToken');

            if (!user || !user.security.isActive) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            res.json({
                success: true,
                data: user
            });

        } catch (error) {
            logger.error('Get profile error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Update user profile
    async updateProfile(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const userId = req.user.userId;
            const updates = req.body;
            const requestInfo = {
                ip: req.ip || req.connection.remoteAddress || 'unknown',
                userAgent: req.get('User-Agent') || 'unknown'
            };

            // Find user
            const user = await User.findById(userId);
            if (!user || !user.security.isActive) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // Track changes for logging
            const changes = {};
            const allowedProfileUpdates = [
                'firstName', 'lastName', 'email', 'phone', 
                'hostelBlock', 'roomNumber', 'department'
            ];

            // Update only allowed profile fields
            allowedProfileUpdates.forEach(field => {
                if (updates[field] !== undefined && updates[field] !== user.profile[field]) {
                    changes[field] = {
                        old: user.profile[field],
                        new: updates[field]
                    };
                    user.profile[field] = updates[field];
                }
            });

            // Check if email is being changed and is unique
            if (changes.email) {
                const existingUser = await User.findOne({
                    'profile.email': updates.email.toLowerCase(),
                    _id: { $ne: userId }
                });

                if (existingUser) {
                    return res.status(400).json({
                        success: false,
                        message: 'Email already exists'
                    });
                }
            }

            // Save changes if any
            if (Object.keys(changes).length > 0) {
                await user.save();

                // Log profile update
                await AccessLog.logAccess({
                    userId: user._id,
                    studentId: user.studentId,
                    action: 'PROFILE_UPDATE',
                    result: 'SUCCESS',
                    details: { changes },
                    session: requestInfo
                });

                logger.info(`Profile updated: ${user.studentId}`, {
                    userId: user._id,
                    changes: Object.keys(changes)
                });
            }

            res.json({
                success: true,
                message: 'Profile updated successfully',
                data: {
                    id: user._id,
                    studentId: user.studentId,
                    role: user.role,
                    profile: user.profile
                }
            });

        } catch (error) {
            logger.error('Update profile error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Change password
    async changePassword(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const { currentPassword, newPassword } = req.body;
            const userId = req.user.userId;
            const requestInfo = {
                ip: req.ip || req.connection.remoteAddress || 'unknown',
                userAgent: req.get('User-Agent') || 'unknown'
            };

            // Find user
            const user = await User.findById(userId);
            if (!user || !user.security.isActive) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // Verify current password
            const isCurrentPasswordValid = await user.comparePassword(currentPassword);
            if (!isCurrentPasswordValid) {
                await AccessLog.logAccess({
                    userId: user._id,
                    studentId: user.studentId,
                    action: 'PASSWORD_CHANGE',
                    result: 'FAILURE',
                    details: { reason: 'Invalid current password' },
                    session: requestInfo
                });

                return res.status(400).json({
                    success: false,
                    message: 'Current password is incorrect'
                });
            }

            // Update password
            user.password = newPassword;
            user.security.loginAttempts = 0;
            user.security.lockUntil = undefined;
            
            await user.save();

            // Log password change
            await AccessLog.logAccess({
                userId: user._id,
                studentId: user.studentId,
                action: 'PASSWORD_CHANGE',
                result: 'SUCCESS',
                session: requestInfo
            });

            logger.info(`Password changed: ${user.studentId}`, {
                userId: user._id
            });

            res.json({
                success: true,
                message: 'Password changed successfully'
            });

        } catch (error) {
            logger.error('Change password error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Get user dashboard data
    async getDashboard(req, res) {
        try {
            const userId = req.user.userId;
            const userRole = req.user.role;

            // Get user details
            const user = await User.findById(userId)
                .select('-password -security.passwordResetToken');

            if (!user || !user.security.isActive) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // Get recent login history
            const loginHistory = await AccessLog.getUserLoginHistory(userId, 5);

            // Role-specific dashboard data
            let dashboardData = {
                user: {
                    id: user._id,
                    studentId: user.studentId,
                    role: user.role,
                    profile: user.profile,
                    lastLogin: user.security.lastLogin
                },
                loginHistory
            };

            // Add role-specific data
            switch (userRole) {
                case 'student':
                    // Add student-specific dashboard data
                    dashboardData.notices = []; // Would fetch from notices collection
                    dashboardData.attendance = {}; // Would fetch attendance data
                    dashboardData.complaints = []; // Would fetch user's complaints
                    break;

                case 'warden':
                    // Add warden-specific dashboard data
                    const totalStudents = await User.countDocuments({ 
                        role: 'student', 
                        'security.isActive': true 
                    });
                    
                    dashboardData.stats = {
                        totalStudents,
                        // Add more warden statistics
                    };
                    break;

                case 'dc':
                    // Add DC-specific dashboard data
                    const userStats = await this.getUserStats();
                    const loginStats = await AccessLog.getLoginStats(7);
                    
                    dashboardData.stats = {
                        ...userStats,
                        loginStats
                    };
                    break;
            }

            res.json({
                success: true,
                data: dashboardData
            });

        } catch (error) {
            logger.error('Get dashboard error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Get user statistics (for admin roles)
    async getUserStats() {
        try {
            const stats = await User.aggregate([
                {
                    $match: { 'security.isActive': true }
                },
                {
                    $group: {
                        _id: '$role',
                        count: { $sum: 1 }
                    }
                }
            ]);

            const totalUsers = await User.countDocuments({ 'security.isActive': true });
            const lockedAccounts = await User.countDocuments({
                'security.isActive': true,
                'security.lockUntil': { $exists: true, $gt: new Date() }
            });

            return {
                totalUsers,
                lockedAccounts,
                roleDistribution: stats,
                lastUpdated: new Date()
            };

        } catch (error) {
            logger.error('Get user stats error:', error);
            return null;
        }
    }

    // Get all users (admin only)
    async getAllUsers(req, res) {
        try {
            // Check if user has permission
            if (req.user.role !== 'warden' && req.user.role !== 'dc') {
                return res.status(403).json({
                    success: false,
                    message: 'Insufficient permissions'
                });
            }

            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const role = req.query.role;
            const search = req.query.search;

            // Build query
            let query = { 'security.isActive': true };
            
            if (role && ['student', 'warden', 'dc'].includes(role)) {
                query.role = role;
            }

            if (search) {
                query.$or = [
                    { studentId: { $regex: search, $options: 'i' } },
                    { 'profile.firstName': { $regex: search, $options: 'i' } },
                    { 'profile.lastName': { $regex: search, $options: 'i' } },
                    { 'profile.email': { $regex: search, $options: 'i' } }
                ];
            }

            // Execute query with pagination
            const users = await User.find(query)
                .select('-password -security.passwordResetToken')
                .sort({ createdAt: -1 })
                .limit(limit * 1)
                .skip((page - 1) * limit);

            const total = await User.countDocuments(query);

            res.json({
                success: true,
                data: {
                    users,
                    pagination: {
                        page,
                        limit,
                        total,
                        pages: Math.ceil(total / limit)
                    }
                }
            });

        } catch (error) {
            logger.error('Get all users error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Create new user (admin only)
    async createUser(req, res) {
        try {
            // Check permissions
            if (req.user.role !== 'warden' && req.user.role !== 'dc') {
                return res.status(403).json({
                    success: false,
                    message: 'Insufficient permissions'
                });
            }

            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const userData = req.body;
            const requestInfo = {
                ip: req.ip || req.connection.remoteAddress || 'unknown',
                userAgent: req.get('User-Agent') || 'unknown'
            };

            // Create new user
            const user = new User(userData);
            await user.save();

            // Log user creation
            await AccessLog.logAccess({
                userId: req.user.userId,
                studentId: req.user.studentId,
                action: 'USER_CREATED',
                result: 'SUCCESS',
                details: { 
                    newUserStudentId: user.studentId,
                    newUserRole: user.role 
                },
                session: requestInfo
            });

            logger.info(`User created: ${user.studentId} by ${req.user.studentId}`, {
                createdBy: req.user.userId,
                newUserId: user._id
            });

            res.status(201).json({
                success: true,
                message: 'User created successfully',
                data: {
                    id: user._id,
                    studentId: user.studentId,
                    role: user.role,
                    profile: user.profile
                }
            });

        } catch (error) {
            if (error.code === 11000) {
                return res.status(400).json({
                    success: false,
                    message: 'Student ID or email already exists'
                });
            }

            logger.error('Create user error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }
}

module.exports = new UserController();