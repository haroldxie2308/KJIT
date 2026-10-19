#!/usr/bin/perl
# What a cross-CPU wake-up costs the waker in the kjit-guest (QEMU virt, GICv2 emulated in
# userspace under HVF: an IPI is a trapped MMIO write). Used by the server-CPU-gap study
# (tests/guest/cpu-gap.sh): redis charges that cost to the server whenever a write(2) wakes a
# sleeping client thread on another CPU.
#
#   perl wake-cost.pl ITERATIONS PERIOD_US ROUNDS
#
# The parent (pinned to CPU 0) writes one byte to a pipe every PERIOD_US microseconds
# (sleeping in select in between) and reads its own se.sum_exec_runtime from
# /proc/self/sched before and after; the child reads the pipe. Variants:
#   remote   child blocked in read(2) on CPU 1: each write wakes it across CPUs
#   local    child blocked in read(2) on CPU 0: each write wakes it on the writer's CPU
#   spin     child polls the pipe non-blocking on CPU 1: the write wakes nobody
#   nowrite  no child, the parent only sleeps (the cost of the loop itself)
# One line per variant and round: "wake variant=<v> round=<r> parent_us_per_iter=<x>
# ipi_per_iter=<y>" (ipi = IPI0 + IPI1 deltas of /proc/interrupts, all CPUs), and for remote
# and local "wakechild variant=<v> child_us_per_wake=<z>": the sleeper's own CPU time per
# wake-up (one blocking read(2) returning one byte), i.e. what a server that blocks in
# epoll_wait pays per block. Variants alternate within a round.
use strict;
use warnings;
use Fcntl;

my ($iters, $period_us, $rounds) = @ARGV;
die "usage: wake-cost.pl ITERATIONS PERIOD_US ROUNDS\n" unless defined $rounds;

sub exec_ns {
    open(my $f, '<', '/proc/self/sched') or die "sched: $!";
    while (<$f>) { return $1 * 1e6 if /^se\.sum_exec_runtime\s*:\s*([0-9.]+)/ }
    die "no sum_exec_runtime";
}

sub ipis {
    open(my $f, '<', '/proc/interrupts') or die "interrupts: $!";
    my $t = 0;
    while (<$f>) {
        next unless /^IPI[01]:/;
        my @c = split;
        shift @c;
        for my $v (@c) { last unless $v =~ /^[0-9]+$/; $t += $v }
    }
    return $t;
}

sub pin { my ($pid, $cpu) = @_; system('taskset', '-cp', $cpu, $pid) == 0 or die "taskset"; }

sub run_variant {
    my ($v) = @_;
    my ($child_cpu, $nonblock) = $v eq 'remote' ? (1, 0) : $v eq 'local' ? (0, 0) : $v eq 'spin' ? (1, 1) : (undef, 0);
    pipe(my $r, my $w) or die "pipe: $!";
    my $pid;
    if (defined $child_cpu) {
        $pid = fork() // die "fork: $!";
        if ($pid == 0) {
            close $w;
            pin($$, $child_cpu);
            fcntl($r, F_SETFL, O_NONBLOCK) if $nonblock;
            my $buf;
            my $c0 = exec_ns();
            while (1) {
                my $n = sysread($r, $buf, 4096);
                last if defined $n && $n == 0;
            }
            printf "wakechild variant=%s child_us_per_wake=%.3f\n", $v, (exec_ns() - $c0) / $iters / 1000 unless $nonblock;
            exit 0;
        }
        close $r;
        select(undef, undef, undef, 0.3);   # let the child settle on its CPU
    }
    pin($$, 0);
    my $i0 = ipis();
    my $t0 = exec_ns();
    for (1 .. $iters) {
        syswrite($w, 'x') if defined $child_cpu;
        select(undef, undef, undef, $period_us / 1e6);
    }
    my $t1 = exec_ns();
    my $i1 = ipis();
    if (defined $child_cpu) { close $w; waitpid($pid, 0); }
    return (($t1 - $t0) / $iters / 1000, ($i1 - $i0) / $iters);
}

for my $round (1 .. $rounds) {
    for my $v (qw(remote local spin nowrite)) {
        my ($us, $ipi) = run_variant($v);
        printf "wake variant=%s round=%d iters=%d period_us=%d parent_us_per_iter=%.3f ipi_per_iter=%.3f\n",
            $v, $round, $iters, $period_us, $us, $ipi;
    }
}
