import face_recognition
import requests
import numpy as np
from PIL import Image
from io import BytesIO


def compare_faces(img1_url, img2_url):

    try:
        img1 = Image.open(BytesIO(requests.get(img1_url).content))
        img2 = Image.open(BytesIO(requests.get(img2_url).content))

        img1 = np.array(img1)
        img2 = np.array(img2)

        enc1 = face_recognition.face_encodings(img1)
        enc2 = face_recognition.face_encodings(img2)

        if enc1 and enc2:
            return face_recognition.compare_faces([enc1[0]], enc2[0])[0]

    except:
        pass

    return False