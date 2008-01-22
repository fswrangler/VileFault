#!/usr/bin/perl

open IN, "ls /dev/pico*c |";
while(<IN>) { $count++ }
close IN;

for(0..$count-1) {
	system("picorw w 0x410 adad /dev/pico".$_."c");
	system("picorw r 0xf4000 2 ".$_);
}

sleep(2);

for(0..$count-1) {
	system("picorw r 0x410 16 /dev/pico".$_."c");
}
