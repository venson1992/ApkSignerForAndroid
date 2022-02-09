package com.android.apksig.util;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Phaser;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public interface RunnablesExecutor {
    public static final RunnablesExecutor MULTI_THREADED = new RunnablesExecutor() {
        /* class com.android.apksig.util.RunnablesExecutor.AnonymousClass1 */
        private final int PARALLELISM = Math.min(32, Runtime.getRuntime().availableProcessors());
        private final int QUEUE_SIZE = 4;

        @Override // com.android.apksig.util.RunnablesExecutor
        public void execute(RunnablesProvider provider) {
            ExecutorService mExecutor = new ThreadPoolExecutor(this.PARALLELISM, this.PARALLELISM, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue(4), new ThreadPoolExecutor.CallerRunsPolicy());
            Phaser tasks = new Phaser(1);
            for (int i = 0; i < this.PARALLELISM; i++) {
                Runnable task = ;
                public static final RunnablesExecutor SINGLE_THREADED = ;

                void execute(RunnablesProvider runnablesProvider);
            }
