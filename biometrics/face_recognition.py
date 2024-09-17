import face_recognition
import cv2

# Load known face images
known_image = face_recognition.load_image_file("known_user.jpg")
known_encoding = face_recognition.face_encodings(known_image)[0]

# Capture video from webcam
video_capture = cv2.VideoCapture(0)

while True:
    ret, frame = video_capture.read()
    rgb_frame = frame[:, :, ::-1]  # Convert BGR to RGB

    # Find all face encodings in the current frame
    face_encodings = face_recognition.face_encodings(rgb_frame)

    for face_encoding in face_encodings:
        match = face_recognition.compare_faces([known_encoding], face_encoding)
        if match[0]:
            print("Authenticated!")
            video_capture.release()
            cv2.destroyAllWindows()
            break

    # Display video
    cv2.imshow('Video', frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

video_capture.release()
cv2.destroyAllWindows()
