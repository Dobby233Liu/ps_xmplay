import struct
with open("MENUSND.BIN", "rb") as f:
  vh_off, vb_off = struct.unpack("<II", f.read(8))
  f.seek(vh_off)
  with open("MENUSND.vh", "wb") as vh:
    vh.write(f.read(vb_off - vh_off))
  f.seek(vb_off)
  with open("MENUSND.vb", "wb") as vh:
    vh.write(f.read())