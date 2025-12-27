"""
NiksES QR Code Decoder

Detect and decode QR codes from image attachments.
"""

import logging
from typing import List, Optional, Tuple
from io import BytesIO

from app.models.email import QRCodeInfo, ExtractedURL
from app.utils.exceptions import QRCodeDecodingError

logger = logging.getLogger(__name__)

# Image MIME types we can process
IMAGE_MIME_TYPES = [
    'image/png', 'image/jpeg', 'image/jpg', 'image/gif',
    'image/bmp', 'image/tiff', 'image/webp'
]

IMAGE_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp']


def decode_qr_codes(attachments: List[dict]) -> List[QRCodeInfo]:
    """
    Find and decode QR codes in image attachments.
    
    Args:
        attachments: List of attachment dictionaries with 'content', 'filename', 'content_type'
        
    Returns:
        List of QRCodeInfo objects for decoded QR codes
    """
    qr_codes = []
    
    for attachment in attachments:
        if not _is_image_file(attachment.get('filename', ''), attachment.get('content_type', '')):
            continue
        
        content = attachment.get('content')
        if not content:
            continue
        
        try:
            qr_info = find_qr_in_image(content, attachment.get('filename', 'unknown'))
            if qr_info:
                qr_codes.append(qr_info)
        except Exception as e:
            logger.debug(f"Error processing image {attachment.get('filename')}: {e}")
    
    return qr_codes


def find_qr_in_image(image_bytes: bytes, filename: str) -> Optional[QRCodeInfo]:
    """
    Find and decode QR code in a single image.
    
    Uses pyzbar and PIL/Pillow for QR code detection.
    
    Args:
        image_bytes: Image content as bytes
        filename: Filename of the image
        
    Returns:
        QRCodeInfo if QR code found, None otherwise
    """
    try:
        from PIL import Image
        from pyzbar import pyzbar
        
        # Open image
        image = Image.open(BytesIO(image_bytes))
        
        # Decode QR codes
        decoded = pyzbar.decode(image)
        
        if not decoded:
            return None
        
        # Take first QR code
        qr = decoded[0]
        raw_data = qr.data.decode('utf-8', errors='ignore')
        
        # Determine data type
        data_type, extracted_url = _decode_qr_data(raw_data)
        
        return QRCodeInfo(
            source_attachment=filename,
            decoded_data=raw_data,
            data_type=data_type,
            extracted_url=extracted_url
        )
        
    except ImportError:
        logger.warning("PIL or pyzbar not installed, QR decoding disabled")
        return None
    except Exception as e:
        logger.debug(f"QR decode error for {filename}: {e}")
        return None


def _is_image_file(filename: str, content_type: str) -> bool:
    """Check if file is an image based on extension or MIME type."""
    # Check MIME type
    if content_type and content_type.lower() in IMAGE_MIME_TYPES:
        return True
    
    # Check extension
    if filename:
        ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        if ext in IMAGE_EXTENSIONS:
            return True
    
    return False


def _decode_qr_data(raw_data: str) -> Tuple[str, Optional[str]]:
    """
    Decode QR data and classify type.
    
    Args:
        raw_data: Raw decoded QR string
        
    Returns:
        Tuple of (data_type, extracted_url)
    """
    raw_lower = raw_data.lower()
    
    # URL
    if raw_lower.startswith(('http://', 'https://', 'www.')):
        url = raw_data
        if url.lower().startswith('www.'):
            url = 'https://' + url
        return 'url', url
    
    # vCard
    if raw_lower.startswith('begin:vcard'):
        return 'vcard', None
    
    # WiFi configuration
    if raw_lower.startswith('wifi:'):
        return 'wifi', None
    
    # Email
    if raw_lower.startswith('mailto:'):
        return 'email', None
    
    # SMS
    if raw_lower.startswith(('sms:', 'smsto:')):
        return 'sms', None
    
    # Phone
    if raw_lower.startswith('tel:'):
        return 'phone', None
    
    # Geo location
    if raw_lower.startswith('geo:'):
        return 'geo', None
    
    # Calendar event
    if raw_lower.startswith('begin:vevent'):
        return 'calendar', None
    
    # Default to text
    return 'text', None


def process_attachments_for_qr(attachments: List[dict]) -> Tuple[List[QRCodeInfo], List[ExtractedURL]]:
    """
    Process attachments for QR codes and extract URLs.
    
    Args:
        attachments: List of attachment dictionaries
        
    Returns:
        Tuple of (qr_codes, extracted_urls)
    """
    qr_codes = decode_qr_codes(attachments)
    
    urls = []
    for qr in qr_codes:
        if qr.extracted_url:
            from app.utils.helpers import extract_domain_from_url, normalize_url
            
            domain = extract_domain_from_url(qr.extracted_url) or ''
            
            urls.append(ExtractedURL(
                url=qr.extracted_url,
                normalized_url=normalize_url(qr.extracted_url),
                domain=domain,
                scheme='https' if qr.extracted_url.startswith('https') else 'http',
                source='qr_code',
                is_shortened=False
            ))
    
    return qr_codes, urls
