#!/bin/sh

framework=DiskImages
fprefix=/System/Library/PrivateFrameworks
output=DiskImages.disassembled.txt

otool -tvV ${fprefix}/${framework}.framework/${framework} |\
c++filt > ${output}

# symbol name is used instead of zero value. fix.
perl -i -pe 's/_ZN8Security10CssmClient8CssmImpl12StandardCssmD1Ev.eh/0x0/g' ${output}
