// Importation des modules nécessaires
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const { verifyToken } = require('../utils/functions');

// Middleware d'authentification
const authMiddleware = async (req, res, next) => {

  const token = req.header('Authorization');

  // Vérification si le token n'est pas fourni
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Accès refusé. Aucun token fourni.'
    });
  }

  // Vérification du token et récupération de l'ID de l'utilisateur
  const userId = verifyToken(req);

  // Si le token est invalide, renvoie une erreur
  if (!userId) {
    return res.status(400).json({
      success: false,
      message: 'Token invalide'
    });
  }

  try {
    // Recherche de l'utilisateur dans la base de données par son ID
    req.user = await User.findById(userId);

    // Si l'utilisateur n'est pas trouvé, renvoie une erreur
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
