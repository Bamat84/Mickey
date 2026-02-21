"""
Mickey auth package — firm-first authentication and authorisation.

Exports:
  auth_bp       Flask blueprint (register with app.register_blueprint)
"""
from auth.routes import auth_bp

__all__ = ["auth_bp"]
