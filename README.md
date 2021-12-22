# Why?
This is an effective re-write of the GDS post/repo by Rory McNamara using bash on binary data to
do process hooking. The original repo can be found here: https://github.com/AonCyberLabs/Cexigua/

I was curious about this for a few reasons:
- I had never done process hooking before.
- I have never directly overwritten the stack before.
- I had never used GNU grep for hunt for ROP gadgets before.

All of that sounded cool, so I re-wrote/am re-writing the scripts to make it more cohesive
and to work slightly better. Eventually, I will want to try overwriting the heap as well to see
what we can do there. 

# What?
What we are doing is:
- launching `sleep 60` and grabbing its PID
- checking sleep and the libraries it's using for ROP gadgets
- using memfd_create to create a file descriptor in raw memory for us to use to execute the target program
- when we have everything we need, we are overwriting the stack using `dd` to point to our target
- when the `nanosleep` call returns (the underpinning command in `sleep`), the IP points to our target program 

# How?
Just run `./overwrite.sh ./target` and see what happens after about 60 seconds.

This works because of the lesser known `/proc/sys/kernel/yama/ptrace_scope` kernel setting. The default 
setting on most Linux systems for this is `1` or `0`, both of which allow us to read the stack address
of PIDs spawned by the user that launches the command (us running `sleep` in this context) or for any
non-admin PID (if the setting is `0`).

# Caveats
While I am improving the script, it is still very brittle. You may have to run the command a few times. 
If you do not see the `exec dd` command in the output, the script failed to complete.
