#!/bin/sh -e
redo-ifchange home warn-auto.sh dnstracesort.sh
(
cat warn-auto.sh
sed 's}HOME}'"`./home`"'}g' dnstracesort.sh
) > "$3"
chmod a+x "$3"
