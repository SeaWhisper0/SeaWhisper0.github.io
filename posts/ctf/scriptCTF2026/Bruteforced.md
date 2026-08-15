# Bruteforced

**Author**: carax49

## Overview

- Category: Forensics
- Description:

```text
Help! Our website got bruteforced. Hopefully the attacker did not leak anything.
```

## Solution

The challenge gives me a file called `log.pcap`. I opened it with Wireshark.

The HTTP packets caught my attention, so I used a filter to pull them out.

![alt text](../../../images/ctf/scriptCTF2026/Bruteforce/image-3.png)

Based on the challenge description and what I saw in Wireshark, this really is a bruteforce attack.

The attacker sent requests one after another:

```text
GET /flag_0 HTTP/1.1
GET /flag_1 HTTP/1.1
GET /flag_2 HTTP/1.1
...
```

But all of them got a `404` status code back.

I wanted to filter for any response with a `200` status code.

![alt text](../../../images/ctf/scriptCTF2026/Bruteforce/image-4.png)

And there was only one result. I followed the HTTP Stream to look closer.

![alt text](../../../images/ctf/scriptCTF2026/Bruteforce/image-5.png)

```text
GET /flag_4919 HTTP/1.1
Host: ctf.scriptsorcerers.xyz
```

As you can see, when the attacker sent the request `GET /flag_4919` to the host `ctf.scriptsorcerers.xyz`, the server returned `200 OK` instead of `404 NOT FOUND`.

I tried visiting

```text
https://ctf.scriptsorcerers.xyz/flag_4919
```

And the flag was right there.

![alt text](../../../images/ctf/scriptCTF2026/Bruteforce/image-6.png)

## Flag

```text
scriptCTF{7h3_h1dd3n_3ndp01n7_g0t_l34k3d}
```