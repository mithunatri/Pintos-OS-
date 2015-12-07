#!/bin/sh

cd build; pintos-mkdisk filesys.dsk --filesys-size=2; pintos -f -q
