"""
FCM (Firebase Cloud Messaging) Service Module
Handles all Firebase Cloud Messaging operations following SOLID principles
"""
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
import firebase_admin
from firebase_admin import credentials, messaging
import logging

logger = logging.getLogger(__name__)


class FCMTemplateFactory:
    """Factory for creating push notification templates (Strategy Pattern)"""
    
    @staticmethod
    def create_rating_template(
        deeplink: str = "",
        custom_payload: Optional[Dict] = None,
        image_link: str = ""
    ) -> Dict[str, Any]:
        """
        Create a Rating push notification template
        
        Args:
            deeplink: URL to navigate to when notification is clicked
            custom_payload: Optional custom JSON payload
            image_link: URL to the notification image
            
        Returns:
            Complete remote message payload
        """
        expiry = int((datetime.now() + timedelta(days=30)).timestamp())
        notification_type = "Image" if image_link else "Simple"
        
        base_payload = {
            "smtSrc": "Smartech",
            "data": {
                "actionButton": [],
                "attrParams": {},
                "carousel": [],
                "customPayload": custom_payload or {},
                "deeplink": deeplink,
                "expiry": expiry,
                "image": image_link,
                "message": "Rating Push Notification",
                "publishedDate": datetime.now().isoformat(),
                "sound": True,
                "status": "sent",
                "subtitle": "",
                "title": "Rating Push Notification",
                "trid": f"175567-591-13872-0-{datetime.now().strftime('%Y%m%d%H%M%S')}-T",
                "type": notification_type
            },
            "trid": f"175567-591-13872-0-{datetime.now().strftime('%Y%m%d%H%M%S')}-T",
            "smtUi": {
                "flid": 1,
                "lid": 1,
                "rat": {
                    "cbt": "Submit",
                    "dl": "",
                    "sc": 5,
                    "si": "https://cdna.netcoresmartech.com/14340/1680080201.png",
                    "ty": 1,
                    "ui": "https://cdna.netcoresmartech.com/14340/1680076013.png"
                }
            },
            "smtCustomPayload": custom_payload or {}
        }
        
        return base_payload
    
    @staticmethod
    def create_simple_template(
        title: str = "Simple Notification",
        message: str = "",
        deeplink: str = "",
        custom_payload: Optional[Dict] = None,
        image_link: str = ""
    ) -> Dict[str, Any]:
        """Create a Simple push notification template"""
        expiry = int((datetime.now() + timedelta(days=30)).timestamp())
        notification_type = "Image" if image_link else "Simple"
        
        base_payload = {
            "smtSrc": "Smartech",
            "data": {
                "actionButton": [],
                "attrParams": {},
                "carousel": [],
                "customPayload": custom_payload or {},
                "deeplink": deeplink,
                "expiry": expiry,
                "image": image_link,
                "message": message,
                "publishedDate": datetime.now().isoformat(),
                "sound": True,
                "status": "sent",
                "subtitle": "",
                "title": title,
                "trid": f"175567-591-13872-0-{datetime.now().strftime('%Y%m%d%H%M%S')}-T",
                "type": notification_type
            },
            "trid": f"175567-591-13872-0-{datetime.now().strftime('%Y%m%d%H%M%S')}-T",
            "smtUi": {},
            "smtCustomPayload": custom_payload or {}
        }
        
        return base_payload
    
    @staticmethod
    def get_available_templates() -> Dict[str, Dict[str, Any]]:
        """Get all available notification templates with their field configurations"""
        return {
            "rating": {
                "name": "Rating Push Notification",
                "fields": {
                    "deeplink": {"type": "text", "label": "Deep Link", "required": False},
                    "customPayload": {"type": "json", "label": "Custom Payload", "required": False}
                }
            },
            "simple": {
                "name": "Simple Push Notification",
                "fields": {
                    "title": {"type": "text", "label": "Title", "required": True},
                    "message": {"type": "text", "label": "Message", "required": True},
                    "deeplink": {"type": "text", "label": "Deep Link", "required": False},
                    "customPayload": {"type": "json", "label": "Custom Payload", "required": False}
                }
            }
        }


class FCMService:
    """Service to handle Firebase Cloud Messaging operations"""
    
    def __init__(self, credentials_path: Optional[str] = None):
        """
        Initialize FCM Service
        
        Args:
            credentials_path: Path to Firebase service account JSON file
        """
        self.credentials_path = credentials_path
        self.is_initialized = False
        
        if credentials_path:
            self.initialize(credentials_path)
    
    def initialize(self, credentials_path: str) -> Tuple[bool, str]:
        """
        Initialize Firebase Admin SDK with credentials
        
        Args:
            credentials_path: Path to Firebase service account JSON
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Check if Firebase app is already initialized
            try:
                firebase_admin.get_app()
                # App already exists, delete it first to reinitialize with new credentials
                firebase_admin.delete_app(firebase_admin.get_app())
                logger.info("Deleted existing Firebase app instance")
            except ValueError:
                # App doesn't exist, which is what we expect on first initialization
                pass
            
            creds = credentials.Certificate(credentials_path)
            firebase_admin.initialize_app(creds)
            self.is_initialized = True
            logger.info(f"Firebase initialized successfully with {credentials_path}")
            return True, "Firebase initialized successfully"
        except Exception as e:
            logger.error(f"Failed to initialize Firebase: {str(e)}")
            return False, f"Failed to initialize Firebase: {str(e)}"
    
    def send_notification(
        self,
        fcm_token: str,
        payload: Dict[str, Any],
        template_type: str = "simple"
    ) -> Tuple[bool, str]:
        """
        Send push notification to device via FCM
        
        Args:
            fcm_token: Firebase Cloud Messaging token
            payload: Notification payload (complete structure with smtSrc, data, trid, smtUi, smtCustomPayload)
            template_type: Type of template used (for logging)
            
        Returns:
            Tuple of (success: bool, message/messageId: str)
        """
        if not self.is_initialized:
            logger.error("Firebase not initialized. Cannot send notification.")
            return False, "Firebase not initialized. Please upload credentials first."
        
        try:
            # Log the complete original payload
            logger.info("="*80)
            logger.info("COMPLETE PAYLOAD BEING SENT:")
            logger.info("="*80)
            logger.info(f"Template Type: {template_type}")
            logger.info(f"FCM Token: {fcm_token}")
            logger.info(f"Full Payload (JSON):\n{json.dumps(payload, indent=2)}")
            logger.info("="*80)
            
            title = payload.get("data", {}).get("title", "")
            body = payload.get("data", {}).get("message", "")
            
            # Convert entire payload to strings for FCM data field
            # FCM data field requires all string values
            data_dict = {}
            
            # Add top-level fields
            if "smtSrc" in payload:
                data_dict["smtSrc"] = str(payload["smtSrc"])
            
            if "trid" in payload:
                data_dict["trid"] = str(payload["trid"])
            
            # Add nested data as JSON string
            if "data" in payload:
                data_dict["data"] = json.dumps(payload["data"])
            
            # Add smtUi as JSON string
            if "smtUi" in payload:
                data_dict["smtUi"] = json.dumps(payload["smtUi"])
            
            # Add smtCustomPayload as JSON string
            if "smtCustomPayload" in payload:
                data_dict["smtCustomPayload"] = json.dumps(payload["smtCustomPayload"])
            
            # Log the converted FCM message data
            logger.info("="*80)
            logger.info("FCM MESSAGE DATA (converted to strings):")
            logger.info("="*80)
            logger.info(f"Data Dict (JSON):\n{json.dumps(data_dict, indent=2)}")
            logger.info("="*80)
            
            # Create Android message with the complete payload structure
            message = messaging.Message(
                data=data_dict,
                android=messaging.AndroidConfig(
                    priority="high",
                    notification=messaging.AndroidNotification(
                        title=title,
                        body=body,
                        sound="default",
                        click_action="FLUTTER_NOTIFICATION_CLICK"
                    )
                ),
                token=fcm_token
            )
            
            # Send the message
            message_id = messaging.send(message)
            logger.info(f"Successfully sent notification to {fcm_token}. Message ID: {message_id}")
            return True, message_id
            
        except Exception as e:
            logger.error(f"Error sending notification to {fcm_token}: {str(e)}")
            return False, f"Error sending notification: {str(e)}"
    
    def validate_credentials(self, credentials_json: str) -> Tuple[bool, str]:
        """
        Validate Firebase credentials JSON
        
        Args:
            credentials_json: JSON string of Firebase credentials
            
        Returns:
            Tuple of (valid: bool, message: str)
        """
        try:
            data = json.loads(credentials_json)
            required_fields = ["type", "project_id", "private_key_id", "private_key", "client_email"]
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                return False, f"Missing required fields: {', '.join(missing_fields)}"
            
            return True, "Credentials are valid"
        except json.JSONDecodeError:
            return False, "Invalid JSON format for credentials"
        except Exception as e:
            return False, f"Validation error: {str(e)}"


class FCMPayloadBuilder:
    """Builder for creating complex FCM payloads (Builder Pattern)"""
    
    def __init__(self, template_type: str):
        """Initialize payload builder with template type"""
        self.template_type = template_type
        self.payload = {}
    
    def set_deeplink(self, deeplink: str) -> 'FCMPayloadBuilder':
        """Set the deeplink for the notification"""
        if "data" in self.payload:
            self.payload["data"]["deeplink"] = deeplink
        return self
    
    def set_custom_payload(self, custom_payload: Dict) -> 'FCMPayloadBuilder':
        """Set custom payload data"""
        if "data" in self.payload:
            self.payload["data"]["customPayload"] = custom_payload
            self.payload["smtCustomPayload"] = custom_payload
        return self
    
    def set_title(self, title: str) -> 'FCMPayloadBuilder':
        """Set notification title"""
        if "data" in self.payload:
            self.payload["data"]["title"] = title
        return self
    
    def set_message(self, message: str) -> 'FCMPayloadBuilder':
        """Set notification message"""
        if "data" in self.payload:
            self.payload["data"]["message"] = message
        return self
    
    def build(self) -> Dict[str, Any]:
        """Build and return the final payload"""
        return self.payload
