---
type: Blog
title: OSINT “FINANCIAL SUPPORTER 2” DEADSEC CTF 2024
date: '2024-07-28'
tags: ['ctf', 'osint', 'writeup', 'deadsec ctf 2024']
draft: false
summary: Best Osint Challenge so far that I solved
---

## Challenge Description

![Screenshot](/static/writeups/fin/1.png)

![2.png](/static/writeups/fin/2.png)

## Solution

We were given the name of the person in the first part of the challenge, which was "Callista Diamante." On Discord, they probably provided a hint with a Twitter link to her account. I used her username "@c411sta" from Twitter on https://whatsmyname.app/, where I found her social profile: https://keybase.io/c411sta/devices and discovered the device.

Flag: "**DEAD\{iphone_14_plus\}**"

I was the second person to solve the second part of this challenge, and it was one of the best challenges I've ever tackled. I started the OSINT with her Twitter account, but nothing seemed interesting there—just random casual tweets. There was nothing mysterious in her following or followers either. Then, I searched for this username on Bing (I personally use this search engine), and this is what I found,

![3.png](/static/writeups/fin/3.png)

This was her Twitter account with the same bio,

![4.png](/static/writeups/fin/4.png)

I opened her Dailymotion account. No videos were uploaded, but I saw something strange: some weird encrypted text and a normal caption that she uses on all of her socials.

![5.png](/static/writeups/fin/5.png)

Apparently, this was something to work with "k4p2fm6A2iFmpoBa7Ce." I tried to decrypt it, but it was a rabbit hole. Then, I opened a random video on Dailymotion and noticed there is always some encryption in the URL of each video, which looks somewhat like this:

![6.png](/static/writeups/fin/6.png)

I entered this encrypted text and boom, we landed on a private video of Greenland sceneries:

![7.png](/static/writeups/fin/7.png)

I saw the whole video but couldn’t find anything. Maybe I missed some details. I found her account too: https://mastodon.social/@c411sta from https://whatsmyname.app/, where I saw this post of hers,

![8.png](/static/writeups/fin/8.png)

It was edited and checked. The last edits were found to be interesting.

![9.png](/static/writeups/fin/9.png)

From this, it is clear the flag is in the video. The title of the private video was "my beautiful country." But where? Let's check Twitter again. Luckily, I found a tweet indicating she's interested in learning animation "frame by frame." This suggests the flag is in a single frame of the video for just a millisecond.

![10.png](/static/writeups/fin/10.png)

But where is the flag? Oh, right!

![11.png](/static/writeups/fin/11.png)

Now we know that the flag is in the corner of the video and located in one of the frames. However, since the video is 2:50 minutes long, it would take hours to check each frame. There should be a solution. Then I saw the caption she uses everywhere, which marked 1:10 of the song “Falling Apart" | "Adi Goldstein.”

![12.png](/static/writeups/fin/12.png)

Okay, now we have everything. I downloaded the video and opened it in VLC because VLC allows us to view each frame of the video using the “E” hotkey. I started to view all frames from the 1:10 timestamp, and at the 1:13 timestamp, I found this.

![Screenshot 2024-07-27 213430.png](/static/writeups/fin/13.png)

Flag: **“dead\{greenland-land_0f_ice\}”**