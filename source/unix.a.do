#!/bin/sh -e
objects="buffer_read.o buffer_write.o coe.o error.o error_str.o error_temp.o fd_copy.o fd_move.o fifo.o lock_ex.o lock_exnb.o ndelay_off.o ndelay_on.o open_append.o open_excl.o open_read.o open_readdir.o open_trunc.o openreadclose.o open_write.o pathexec_env.o pathexec_run.o prot.o readclose.o seek_set.o socket_accept.o socket_bind.o socket_conn.o socket_delay.o socket_is.o socket_listen.o socket_local4.o socket_opts.o socket_recv.o socket_remote.o socket_send.o socket_tcp.o socket_udp.o wait_nohang.o wait_pid.o wait_snh.o wait_stop.o"
redo-ifchange makelib ${objects}
exec ./makelib "$3" ${objects}
