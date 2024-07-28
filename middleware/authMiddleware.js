const User = require('../models/userModel');
const { verifyToken } = require('../utils/functions');

// Authentification Middleware
const authMiddleware = async (req, res, next) => {

  const token = req.header('Authorization');

  // Check if the token is not provided
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Accès refusé. Aucun token fourni.'
    });
  }

  // Verify the token and retrieve the user ID
  const userId = verifyToken(req);

  // If the token is invalid, return an error
  if (!userId) {
    return res.status(400).json({
      success: false,
      message: 'Token invalide'
    });
  }

  try {
    // Recherche de l'utilisateur dans la base de données par son ID
    req.user = await User.findById(userId);

    // Search for the user in the database by their ID
    if (!req.user) {
      return res.status(404).json({
        success: false,
        message: 'Utilisateur non trouvé'
      });
    }

    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Erreur serveur'
    });
  }
};

module.exports = authMiddleware;
