image steganography system that hides and recovers 
messages using a desktop GUI and CLI, combining robust least‑significant‑bit (LSB) 
embedding with AES‑256‑GCM encryption for confidentiality and integrity. To resist minor 
distortions and bit flips, it uses adjacent bit repetition with majority voting (8× header, 3× 
payload), and recommends lossless PNG output to preserve LSBs and ensure reliable 
decryption. The GUI includes image previews, a capacity estimator, a live text counter, a 
method selector (Robust LSB or experimental DCT), and visual feedback via a progress bar 
and status bar, enabling an end‑to‑end workflow: encrypt plaintext, embed ciphertext, and 
extract/decrypt to recover the original message. 
