
from pathlib import Path
import os

def removeCert(path):
	print("certrem")
	print(path)
	out = str(path) + ".nosig"
	os.system(f"osslsigncode remove-signature {path} {out}")

def stripZero(path):
	with open(path,'rb') as f:
		data = f.read()

	# strip extra zeros at end of file

	num_trailing = -1

	while True:
		# continue until we find a none 00 char
		print(num_trailing)
		if num_trailing < -10:
			break
		chunk = num_trailing
		chunk += 1
		if chunk == 0:
			val = data[num_trailing:]
		else:
			val = data[num_trailing:chunk]
		if val != b"\x00":
			break
		num_trailing -= 1

	num_trailing += 2
	new_path = str(path) + ".nozero"
	if num_trailing == 0:
		print(f"no padding detected in {path}")
		#rename the file instead
		os.rename(path,new_path)
	else:
		print(f"{path} Trailing zeros to be deleted: {data[num_trailing:]}")
		#remove old file
		os.remove(path)
		with open(new_path, "wb+") as f:
			f.write(data[:num_trailing])

def main():
	for path in Path('signed').rglob('*.exe'):
		removeCert(path)

	for path in Path('signed').rglob('*.nosig'):
		if "export" in str(path):
			print(path)
			stripZero(path)
		else:
			stripZero(path)

	for path in Path("orig").rglob("*.exe"):
		compare = str(path).replace("orig","signed")
		compare += ".nosig.nozero"
		print(compare)
		if os.path.isfile(compare):
			os.system(f"bash -c \"diff <(xxd {path}) <(xxd {compare})\"")

main()
