That's the test for your detect_distributed_scan function.

It's a special "Decoy Scan" designed to look like an attack from many different IPs at the same time.

Here's a breakdown of the command:

nmap: Runs the Nmap tool.

-D RND:30: This is the "Decoy" flag. It tells Nmap to generate 30 random, fake source IPs (RND:30) and launch the scan from all of them (plus your own real IP).

10.111.254.131: This is the target (your Victim PC).

-p 80: It tells Nmap to only scan port 80.

-n: This just means "No DNS resolution" (it makes the scan faster).


nmap -D RND:30 10.111.254.131 -p 80 -n
