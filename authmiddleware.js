const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Role = require('../models/Role');
const { JWT_SECRET } = require('../config/keys');
const logger = require('../utils/logger');

class AuthMiddleware {
    // Verify JWT token
    async verifyToken(req, res, next) {
        try {
            let token;

            // Check for token in header
            if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
                token = req.headers.authorization.split(' ')[1];
            }
            // Check for token in cookies (if using cookie-based auth)
            else if (req.cookies && req.cookies.token) {
                token = req.cookies.token;
            }

            if (!token) {
                return res.status(401).json({
                    success: false,
                    message: 'Access denied. No token provided.'
                });
            }

            try {
                // Verify token
                const decoded = jwt.verify(token, JWT_SECRET);
                
                // Check if user still exists and is active
                const user = await User.findById(decoded.userId)
                    .select('-password -security.passwordResetToken');

                if (!user || !user.security.isActive) {
                    return res.status(401).json({
                        success: false,
                        message: 'Token is no longer valid'
                    });
                }

                // Check if account is locked
                if (user.isLocked) {
                    return res.status(423).json({
                        success: false,
                        message: 'Account is temporarily locked'
                    });
                }

                // Add user info to request
                req.user = {
                    userId: user._id,
                    studentId: user.studentId,
                    role: user.role,
                    profile: user.profile
                };

                next();

            } catch (jwtError) {
                if (jwtError.name === 'TokenExpiredError') {
                    return res.status(401).json({
                        success: false,
                        message: 'Token has expired'
                    });
                } else if (jwtError.name === 'JsonWebTokenError') {
                    return res.status(401).json({
                        success: false,
                        message: 'Invalid token'
                    });
                } else {
                    throw jwtError;
                }
            }

        } catch (error) {
            logger.error('Token verification error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Check user role
    authorize(...allowedRoles) {
        return (req, res, next) => {
            try {
                if (!req.user) {
                    return res.status(401).json({
                        success: false,
                        message: 'Authentication required'
                    });
                }

                if (!allowedRoles.includes(req.user.role)) {
                    logger.warn(`Unauthorized access attempt: ${req.user.studentId} tried to access ${req.originalUrl}`, {
                        userId: req.user.userId,
                        role: req.user.role,
                        requiredRoles: allowedRoles,
                        ip: req.ip
                    });

                    return res.status(403).json({
                        success: false,
                        message: 'Insufficient permissions'
                    });
                }

                next();
            } catch (error) {
                logger.error('Authorization error:', error);
                res.status(500).json({
                    success: false,
                    message: 'Internal server error'
                });
            }
        };
    }

    // Check specific permission
    checkPermission(permissionName) {
        return async (req, res, next) => {
            try {
                if (!req.user) {
                    return res.status(401).json({
                        success: false,
                        message: 'Authentication required'
                    });
                }

                // Get user role permissions
                const role = await Role.findByName(req.user.role);
                if (!role || !role.isActive) {
                    return res.status(403).json({
                        success: false,
                        message: 'Invalid role'
                    });
                }

                // Check if user has the required permission
                if (!role.hasPermission(permissionName)) {
                    logger.warn(`Permission denied: ${req.user.studentId} lacks ${permissionName} permission`, {
                        userId: req.user.userId,
                        role: req.user.role,
                        requiredPermission: permissionName,
                        ip: req.ip
                    });

                    return res.status(403).json({
                        success: false,
                        message: `Permission denied: ${permissionName} required`
                    });
                }

                // Add permissions to request for later use
                req.permissions = role.permissions;
                
                next();
            } catch (error) {
                logger.error('Permission check error:', error);
                res.status(500).json({
                    success: false,
                    message: 'Internal server error'
                });
            }
        };
    }

    // Optional authentication (doesn't fail if no token)
    optionalAuth(req, res, next) {
        if (!req.headers.authorization) {
            return next();
        }

        // Use the main verifyToken but don't fail on missing token
        this.verifyToken(req, res, (error) => {
            if (error && error.status === 401) {
                // Continue without authentication
                return next();
            }
            return next(error);
        });
    }

    // Check if user owns the resource or has admin privileges
    ownerOrAdmin(resourceUserIdField = 'userId') {
        return (req, res, next) => {
            try {
                if (!req.user) {
                    return res.status(401).json({
                        success: false,
                        message: 'Authentication required'
                    });
                }

                const resourceUserId = req.params[resourceUserIdField] || req.body[resourceUserIdField];
                const isOwner = req.user.userId.toString() === resourceUserId;
                const isAdmin = ['warden', 'dc'].includes(req.user.role);

                if (!isOwner && !isAdmin) {
                    return res.status(403).json({
                        success: false,
                        message: 'Access denied. You can only access your own resources.'
                    });
                }

                next();
            } catch (error) {
                logger.error('Ownership check error:', error);
                res.status(500).json({
                    success: false,
                    message: 'Internal server error'
                });
            }
        };
    }

    // Rate limiting for sensitive operations
    sensitiveOperationLimit(req, res, next) {
        // This could integrate with express-rate-limit for more sophisticated limiting
        // For now, it's a placeholder for additional security checks
        const sensitiveOperations = [
            'password-reset',
            'role-assignment',
            'user-creation',
            'permission-update'
        ];

        const operation = req.path.split('/').pop();
        
        if (sensitiveOperations.includes(operation)) {
            // Log sensitive operation attempt
            logger.info(`Sensitive operation attempted: ${operation}`, {
                userId: req.user?.userId,
                studentId: req.user?.studentId,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
        }

        next();
    }

    // Validate student ID format
    validateStudentId(req, res, next) {
        const { studentId } = req.body;
        
        if (studentId && !/^[A-Z0-9]+$/.test(studentId.toUpperCase())) {
            return res.status(400).json({
                success: false,
                message: 'Invalid student ID format'
            });
        }

        next();
    }

    // Check if user can access specific hostel block (for students)
    checkHostelBlockAccess(req, res, next) {
        try {
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required'
                });
            }

            // If user is admin (warden/dc), allow access to all blocks
            if (['warden', 'dc'].includes(req.user.role)) {
                return next();
            }

            // For students, check if they're accessing their own block
            const requestedBlock = req.params.block || req.body.block || req.query.block;
            const userBlock = req.user.profile.hostelBlock;

            if (requestedBlock && requestedBlock !== userBlock) {
                return res.status(403).json({
                    success: false,
                    message: 'You can only access your own hostel block'
                });
            }

            next();
        } catch (error) {
            logger.error('Hostel block access check error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }

    // Add request metadata
    addRequestMetadata(req, res, next) {
        req.requestMetadata = {
            timestamp: new Date(),
            ip: req.ip || req.connection.remoteAddress || 'unknown',
            userAgent: req.get('User-Agent') || 'unknown',
            method: req.method,
            path: req.path,
            query: req.query
        };

        next();
    }
}

module.exports = new AuthMiddleware();