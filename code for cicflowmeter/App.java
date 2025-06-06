package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.guava.GuavaMgr;
import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.FlowFeature;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;
import cic.cs.unb.ca.jnetpcap.worker.TrafficFlowWorker;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;

import javax.swing.*;
import java.awt.EventQueue;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class App {

    private static final String TOPIC             = "CicFlowmeter";
    private static final String BOOTSTRAP_SERVERS = "localhost:9092";
    private static final Logger logger = Logger.getLogger(App.class.getName());

    // single-threaded CSV writer
    private static ExecutorService csvWriterThread;
    // single, long-lived Kafka producer
    private static Producer<String,String> kafkaProducer;

    /** Initialize FlowMgr, GuavaMgr, CSV executor and the one KafkaProducer */
    public static void init() {
        // 1) CSV writer
        csvWriterThread = Executors.newSingleThreadExecutor();

        // 2) FlowMgr & GuavaMgr
        FlowMgr.getInstance().init();
        GuavaMgr.getInstance().init();

        // 3) ONE shared KafkaProducer
        Properties props = new Properties();
        props.put("bootstrap.servers",      BOOTSTRAP_SERVERS);
        props.put("acks",                   "all");
        props.put("enable.idempotence",     "true");
        props.put("key.serializer",         "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer",       "org.apache.kafka.common.serialization.StringSerializer");
        kafkaProducer = new KafkaProducer<>(props);

        // 4) JVM shutdown hook to close resources cleanly
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down CSV writer and Kafka producer...");
            csvWriterThread.shutdownNow();
            kafkaProducer.flush();
            kafkaProducer.close();
            System.out.println("Shutdown complete.");
        }));
    }

    public static void main(String[] args) {
        // configure file logging
        try {
            FileHandler fh = new FileHandler("features.log");
            fh.setFormatter(new SimpleFormatter());
            logger.addHandler(fh);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // start the Swing capture worker on the EDT
        EventQueue.invokeLater(() -> {
            try {
                init();
                GuavaMgr.getInstance().getEventBus().register(App.class);
                App app = new App();
                app.startTrafficFlow();
            } catch (Exception e) {
                System.err.println("Startup error: " + e.getMessage());
            }
        });

        // keep the JVM alive without busy‐spinning
        while (true) {
            try {
                Thread.sleep(60_000);
            } catch (InterruptedException ignored) {
            }
        }
    }

    /** Called by TrafficFlowWorker whenever a new flow arrives */
    private void insertFlow(BasicFlow flow) {
        // 1) Write to CSV
        List<String> rows = new ArrayList<>();
        rows.add(flow.dumpFlowBasedFeaturesEx());
        String header   = FlowFeature.getHeader();
        String path     = FlowMgr.getInstance().getSavePath();
        String filename = LocalDate.now() + FlowMgr.FLOW_SUFFIX;
        csvWriterThread.execute(new InsertCsvRow(header, rows, path, filename));

        // 2) Local file log
        logger.info(rows.get(0));

        // 3) Send to Kafka via the single producer
        for (String line : rows) {
            kafkaProducer.send(
                new ProducerRecord<>(TOPIC, null, line),
                (meta, ex) -> {
                    if (ex != null) {
                        System.err.println("❌ Kafka send failed: " + ex.getMessage());
                    } else {
                        System.out.println("✅ Sent to Kafka: " + line);
                    }
                }
            );
        }
    }

    /** Sets up and launches your packet‐capture → flow‐gen → insertFlow loop */
    private void startTrafficFlow() {
        String ifName = "\\Device\\NPF_{A4BAE19D-8199-4C19-968A-1426074FD111}";
        if (mWorker != null && !mWorker.isCancelled()) return;

        mWorker = new TrafficFlowWorker(ifName);
        mWorker.addPropertyChangeListener(evt -> {
            switch (evt.getPropertyName()) {
                case "progress":
                    System.out.println(evt.getNewValue());
                    break;
                case TrafficFlowWorker.PROPERTY_FLOW:
                    insertFlow((BasicFlow) evt.getNewValue());
                    break;
                case "state":
                    switch (mWorker.getState()) {
                        case STARTED:
                            System.out.println("Worker started.");
                            break;
                        case DONE:
                            try {
                                System.out.println(mWorker.get());
                            } catch (CancellationException|InterruptedException|ExecutionException ex) {
                                System.err.println("Worker error: " + ex.getMessage());
                            }
                            break;
                    }
                    break;
            }
        });
        mWorker.execute();
    }

    private TrafficFlowWorker mWorker;
}