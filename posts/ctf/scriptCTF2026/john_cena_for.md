# John Cena
**Author**: lucas

## Overview
- This is a forensics challenge that provides an image file, `enc.png`.
- The idea: compare `enc.png` with the original image to find the bits that differ.
- Description:
```text
You can't see me!
```

## Analysis
- I first tried common tools such as `strings`, `exiftool`, and `binwalk` to inspect the file, but found nothing interesting.
- Because only a small number of bits seem to differ from the original file, the approach is to download the original image and compare it against `enc.png`.

## Solution
```python
#!/usr/bin/env python3
# flag = LSB(enc) XOR LSB(cover)
import numpy as np, urllib.request, io
from PIL import Image

# Download the original image from Wikipedia
# https://en.wikipedia.org/wiki/John_Cena
enc = np.array(Image.open("./enc.png").convert("RGB")).astype(int)
cover = np.array(Image.open("./origin.jpg").convert("RGB")).astype(int)

# Diff the two images to find the changed bits
delta = enc - cover
ys, xs, cs = np.nonzero(delta)
print(ys)  # row
print(xs)  # column 0
print(cs)  # channel 2 (blue)

'''
[  1   2   3   6   7   9  10  14  15  17  18  19  22  25  26  28  31  33
  34  35  41  42  43  45  49  54  55  57  59  61  65  69  70  73  74  75
  76  78  79  81  82  83  84  87  90  91  97  98  99 101 103 105 107 108
 109 110 111 113 114 118 119 122 123 125 129 130 132 133 134 137 138 139
 141 145 147 148 149 150 151 153 154 155 158 159 162 163 166 167 170 171
 174 175 177 179 180 181 182 183 185 186 188 189 191 194 195 198 199 201
 203 204 205 206 207 209 210 211 213 215 217 218 220 221 222 225 226 228
 229 234 235 238 239 242 243 245 247 250 251 253 255 257 259 260 261 262
 263 265 266 267 268 271 274 275 281 282 283 285 287 289 291 292 293 294
 295 297 298 299 302 303 306 307 310 311 314 315 318 319 321 323 324 325
 326 327 329 330 332 333 335 338 339 342 343 346 347 348 349 350 351 354
 355 356 357 358 359 362 363 364 365 366 367 369 370 371 372 373 375]

A missing position means bit 0.

Example: missing positions 0, 4, 5, 8 => result: 0 1 1 1 0 0 1 1 0 .... => [0 1 1 1 0 0 1 1] => 's' character
'''

bits = (delta[:, 0, 2] != 0).astype(np.uint8)          # column 0, channel 2 (blue)
print(bits)
n = len(bits) // 8 * 8
msg = np.packbits(bits[:n]).tobytes()
print("[+] " + msg.split(b"}")[0].decode() + "}")
```