#!/bin/bash

# First gather some information from the user
# and give them some information.

# What is the name of the site?
RIPPEDSITE=

# What is the location to put this stuff in?
FOLDERNAME




# Here is the wget web rip command
wget --limit-rate=200k --no-clobber --random-wait -r -p -E -e robots=off -U mozilla http://$RIPPEDSITE


# OK, now that I have ripped the site. 
#
#
# Let's check the files names and do any cleanup we need to do.
find /tmp/ -depth -name "* *" -execdir rename 's/ /_/g' "{}" \;
#
#
# First let's make some directories for the image files
mkdir jpg,png,gif,tif
#
#
# Now let's move some picture files around.
find $FOLDERNAME -iname "*.jpg" -exec cp {} jpg
find $FOLDERNAME -iname "*.jpg" -exec cp {} png
find $FOLDERNAME -iname "*.jpg" -exec cp {} gif
find $FOLDERNAME -iname "*.jpg" -exec cp {} tif
#



