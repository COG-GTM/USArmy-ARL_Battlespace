"""
Security utilities for ARL Battlespace - STIG Compliant
Implements V-220631 (Input Validation) and V-220632 (Input Sanitization)

This module provides secure serialization and input validation to replace
unsafe pickle usage and add proper input validation.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union


class SecureSerializer:
    """
    Secure JSON-based serialization to replace pickle.
    Pickle is vulnerable to arbitrary code execution (STIG V-220631/V-220632).
    """
    
    @staticmethod
    def serialize(data: Any) -> bytes:
        """
        Serialize data to JSON bytes.
        
        Args:
            data: Data to serialize (must be JSON-serializable)
            
        Returns:
            JSON-encoded bytes
        """
        return json.dumps(data, default=SecureSerializer._json_encoder).encode('utf-8')
    
    @staticmethod
    def deserialize(data: bytes) -> Any:
        """
        Deserialize JSON bytes to Python object.
        
        Args:
            data: JSON-encoded bytes
            
        Returns:
            Deserialized Python object
        """
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return json.loads(data)
    
    @staticmethod
    def _json_encoder(obj: Any) -> Any:
        """Custom JSON encoder for game objects."""
        if hasattr(obj, '__dict__'):
            # For game objects, extract serializable attributes
            result = {'__class__': obj.__class__.__name__}
            for key, value in obj.__dict__.items():
                if not key.startswith('_'):
                    try:
                        json.dumps(value)
                        result[key] = value
                    except (TypeError, ValueError):
                        # Skip non-serializable attributes
                        if isinstance(value, tuple):
                            result[key] = list(value)
                        elif hasattr(value, '__name__'):
                            result[key] = value.__name__
            return result
        elif isinstance(obj, tuple):
            return list(obj)
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class InputValidator:
    """
    Input validation utilities implementing STIG V-220631.
    Uses whitelist approach for all validations.
    """
    
    # Valid IP address pattern (IPv4)
    IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    
    # Valid hostname pattern
    HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """
        Validate IPv4 address format.
        
        Args:
            ip: IP address string to validate
            
        Returns:
            True if valid IPv4 address, False otherwise
        """
        if not isinstance(ip, str):
            return False
        if ip == 'localhost':
            return True
        return bool(InputValidator.IP_PATTERN.match(ip))
    
    @staticmethod
    def validate_position(position: Any, board_size: Tuple[int, int, int] = (10, 11, 2)) -> bool:
        """
        Validate game position coordinates.
        
        Args:
            position: Position tuple (x, y, z) to validate
            board_size: Maximum board dimensions (default: 10x11x2)
            
        Returns:
            True if valid position within board bounds, False otherwise
        """
        if not isinstance(position, (tuple, list)):
            return False
        if len(position) != 3:
            return False
        
        try:
            x, y, z = int(position[0]), int(position[1]), int(position[2])
        except (TypeError, ValueError):
            return False
        
        # Validate within board bounds
        if not (0 <= x < board_size[0]):
            return False
        if not (0 <= y < board_size[1]):
            return False
        if not (0 <= z < board_size[2]):
            return False
        
        return True
    
    @staticmethod
    def validate_orientation(orientation: Any) -> bool:
        """
        Validate unit orientation vector.
        
        Args:
            orientation: Orientation tuple (x, y, z) to validate
            
        Returns:
            True if valid orientation, False otherwise
        """
        if not isinstance(orientation, (tuple, list)):
            return False
        if len(orientation) != 3:
            return False
        
        try:
            x, y, z = int(orientation[0]), int(orientation[1]), int(orientation[2])
        except (TypeError, ValueError):
            return False
        
        # Orientation values should be -1, 0, or 1
        valid_values = {-1, 0, 1}
        return x in valid_values and y in valid_values and z in valid_values
    
    @staticmethod
    def validate_player_id(player_id: Any, max_players: int = 4) -> bool:
        """
        Validate player ID.
        
        Args:
            player_id: Player ID to validate
            max_players: Maximum number of players (default: 4)
            
        Returns:
            True if valid player ID, False otherwise
        """
        try:
            pid = int(player_id)
            return 0 <= pid < max_players
        except (TypeError, ValueError):
            return False
    
    @staticmethod
    def validate_unit_id(unit_id: Any, max_units: int = 25) -> bool:
        """
        Validate unit ID.
        
        Args:
            unit_id: Unit ID to validate
            max_units: Maximum number of units (default: 25 for 5 units * 5 players)
            
        Returns:
            True if valid unit ID, False otherwise
        """
        try:
            uid = int(unit_id)
            return 0 <= uid < max_units
        except (TypeError, ValueError):
            return False
    
    @staticmethod
    def validate_game_message(data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate a game message structure.
        
        Args:
            data: Message dictionary to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(data, dict):
            return False, "Message must be a dictionary"
        
        if "contents" not in data:
            return False, "Message must have 'contents' field"
        
        valid_contents = {
            "PlayerID", "TeamID", "RemoteAgent", "requestActions",
            "updateClient", "Game Over", "AgentDict"
        }
        
        if data["contents"] not in valid_contents:
            return False, f"Invalid message type: {data['contents']}"
        
        return True, ""


class InputSanitizer:
    """
    Input sanitization utilities implementing STIG V-220632.
    Removes dangerous characters to prevent injection attacks.
    """
    
    # Characters to remove for security
    DANGEROUS_CHARS = re.compile(r'[<>"\';&|`$()]')
    
    @staticmethod
    def sanitize_string(user_input: str, max_length: int = 255) -> Optional[str]:
        """
        Sanitize a string by removing dangerous characters.
        
        Args:
            user_input: String to sanitize
            max_length: Maximum allowed length (default: 255)
            
        Returns:
            Sanitized string or None if input is invalid
        """
        if not isinstance(user_input, str):
            return None
        
        # Remove dangerous characters
        sanitized = InputSanitizer.DANGEROUS_CHARS.sub('', user_input.strip())
        
        # Enforce length limit
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized if sanitized else None
    
    @staticmethod
    def sanitize_ip_address(ip: str) -> Optional[str]:
        """
        Sanitize and validate an IP address.
        
        Args:
            ip: IP address string to sanitize
            
        Returns:
            Sanitized IP address or None if invalid
        """
        if not isinstance(ip, str):
            return None
        
        sanitized = ip.strip()
        
        if InputValidator.validate_ip_address(sanitized):
            return sanitized
        
        return None
