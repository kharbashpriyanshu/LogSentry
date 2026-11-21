from PIL import Image

src = r"C:/Users/PRIYANSHU/.gemini/antigravity/brain/72e2002c-9880-4dbc-81ea-66c4fd9f61fc/.user_uploaded/media_1795258716068_6ec20a23.png"
img = Image.open(src)
bbox = img.getbbox()
print("BBox:", bbox)
cropped = img.crop(bbox)
print("Cropped size:", cropped.size)
cropped.save("frontend/public/branding/logo_full.png")
