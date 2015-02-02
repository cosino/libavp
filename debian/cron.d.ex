#
# Regular cron jobs for the libavp package
#
0 4	* * *	root	[ -x /usr/bin/libavp_maintenance ] && /usr/bin/libavp_maintenance
