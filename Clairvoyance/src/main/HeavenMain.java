package main;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;//パケットクラス
import org.jnetpcap.packet.PcapPacketHandler;//パケットハンドラクラス
import org.jnetpcap.protocol.tcpip.Udp;

public class HeavenMain implements Runnable {
	private static final String PROPERTIES = "properties.xml";
	private static final String STARTUP_MESSAGE = "Heaven Standby";
	private static final int INFINITE = 0;
	private static final String PACKET_MODELDATA = "3D";
	private static final String PACKET_LIVE = "80";
	private static final String PACKET_BULLET = "15";
	private static final int BULLET_SIZE = 52;
	private Properties prop = new Properties();
	private String outputPath = "";
	private String address = "";
	private int port = 0;
	private boolean debug = false;
	private String debugOutputPath = "";

	private StringBuilder writeSpooler = new StringBuilder();// ファイルに書き込む文字列
	private StringBuilder debugWriteSpooler = new StringBuilder();// デバッグ用ファイルに書き込む文字列

	private Thread thread;

	private File file = null;
	private BufferedWriter bw = null;

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		HeavenMain main = new HeavenMain();
	}

	public HeavenMain() {
		System.out.println(STARTUP_MESSAGE);
		try {
			// プロパティ読み込み
			System.out.println("Loading Property:");
			loadProperty();
			// プロパティ表示
			System.out.println("\tOutput Path\t" + outputPath);
			System.out.println("\tIP Address\t" + address);
			System.out.println("\tPort\t" + port);
			System.out.println("\tDebug\t" + debug);
			System.out.println("\tDebug Output Path\t" + debugOutputPath);

			// ファイル書き込み用スレッド
			// thread = new Thread(this);
			// thread.start();

			// ネットワークインターフェースを検索
			List<PcapIf> alldevs = new ArrayList<PcapIf>(); // NIC一覧
			StringBuilder errbuf = new StringBuilder(); // エラーメッセージ格納用

			int r = Pcap.findAllDevs(alldevs, errbuf);

			// ネットワークインターフェースが見つからない場合エラー
			if (r != Pcap.OK || alldevs.isEmpty()) {
				System.err.printf("Can't read list of devices, error is %s\n",
						errbuf.toString());
				return;
			}

			// ネットワークインターフェースを一覧表示
			System.out.println("Network devices found:");
			int i = 0;
			for (PcapIf device : alldevs) {
				String description = (device.getDescription() != null) ? device
						.getDescription() : "No description available";
				System.out.printf("\t#%d: %s [%s]\n", i++, device.getName(),
						description);
			}

			// インターフェースを選択する
			System.out.println("Select Network devices:");
			System.out.println("\tChoose Network devices Number\t");

			BufferedReader br = new BufferedReader(new InputStreamReader(
					System.in));
			PcapIf device = alldevs.get(Integer.parseInt(br.readLine()));
			System.out.printf("\nChoosing '%s' on your behalf:\n", (device
					.getDescription() != null) ? device.getDescription()
					: device.getName());

			// キャプチャ準備
			int snaplen = 64 * 1024; // Capture all packets, no trucation
			// int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
			int flags = Pcap.MODE_NON_PROMISCUOUS;
			int timeout = 3 * 1000; // 1 seconds in millis
			Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags,
					timeout, errbuf);
			if (pcap == null) {
				System.err.printf(
						"Error while opening device for capture: %s\n",
						errbuf.toString());
				return;
			}
			// フィルタ設定
			PcapBpfProgram program = new PcapBpfProgram();
			String expression = "ip and udp and host " + address + " and port "
					+ port;
			// String expression = "ip and udp and dst host " + address +
			// " and dst port " + port;
			int optimize = 1; // 0 = false
			int netmask = 0xFFFFFF00; // 255.255.255.0

			if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {
				System.err.println(pcap.getErr());
				return;
			}

			if (pcap.setFilter(program) != Pcap.OK) {
				System.err.println(pcap.getErr());
				return;
			}
			// キャプチャ開始
			HeavenPacketHandler BulletHandler = new HeavenPacketHandler();

			try {
				// パケットをキャプチャし続ける
				// 紆余曲折あってこうなった
				// いつか直す
				// pcap.loop(INFINITE, BulletHandler, "");
				while (true) {
					pcap.loop(1, BulletHandler, "");
				}
			} finally {
				pcap.close();
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void loadProperty() throws IOException {
		InputStream is = new FileInputStream(PROPERTIES);
		prop.loadFromXML(is);

		outputPath = prop.getProperty("outputPath");
		address = prop.getProperty("IPAddress");
		port = Integer.parseInt(prop.getProperty("port"));
		debug = Boolean.parseBoolean(prop.getProperty("debug"));
		debugOutputPath = prop.getProperty("debugOutputPath");
	}

	// キャプチャーしたパケットを解析する内部クラス
	public class HeavenPacketHandler implements PcapPacketHandler<String> {

		private Udp udp = new Udp();
		private byte[] b = null;
		private ByteBuffer bb = null;
		private long start, stop; // 処理速度測定用

		public HeavenPacketHandler() {
			super();
		}

		@Override
		public void nextPacket(PcapPacket packet, String user) {
			try {
				// start = System.currentTimeMillis();

				// TODO Auto-generated method stub
				// パケットはUDPか
				if (packet.hasHeader(udp)) {
					// パケットをUDPとして解析
					packet.scan(Udp.ID);
					// パケットのデータ部分を抽出
					b = udp.getPayload();
					// モデルデータの通信か判別する
					if (PACKET_MODELDATA.equals(bytesToHex(b[0]))) {
						// ARM弾の射撃情報か判別する
						if (PACKET_BULLET.equals(bytesToHex(b[4]))) {
							// データの解析
							decodeData(b);
							System.out.println(((b.length - 6) / 52)
									+ " Bullet(s) Detected");
						}
					}
					// デバッグモード
					if (debug) {
						// stop = System.currentTimeMillis();
						// writeFile(debugOutputPath, String.valueOf(start));
						// writeFile(debugOutputPath, String.valueOf(stop -
						// start));
						outputHex(b);
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		// 抽出したデータ部を解析して出力する
		public void decodeData(byte[] b) {
			bb = ByteBuffer.wrap(b);
			bb.order(ByteOrder.LITTLE_ENDIAN);
			// データを読み込む準備
			try {
				// ヘッダ部分を読み飛ばす
				bb.getShort();
				bb.get();
				bb.get();
				bb.getShort();
				StringBuilder str = new StringBuilder();
				for (int i = 0; i < (b.length - 6) / BULLET_SIZE; i++) {
					str.append("{");
					// データを抽出
					str.append("x=" + bb.getFloat() + ",");
					str.append("y=" + bb.getFloat() + ",");
					str.append("z=" + bb.getFloat() + ",");
					str.append("vx=" + bb.getFloat() + ",");
					str.append("vy=" + bb.getFloat() + ",");
					str.append("vz=" + bb.getFloat() + ",");
					str.append("option=" + bb.getFloat());
					bb.getFloat();// 用途不明 読み出しはするけど利用はしない
					bb.getFloat();
					bb.getFloat();
					bb.getFloat();
					bb.getFloat();
					bb.getFloat();
					str.append("};");
				}
				// writeSpooler(str.toString(), false);
				writeDirect(str.toString(), false);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		// デバッグ用
		// HEXを出力する
		public void outputHex(byte[] b) {
			// writeSpooler(bytesToHex(b), true);
			writeDirect(bytesToHex(b), true);
		}

		// ファイル書き込み用スプーラーに書き込み
		public void writeSpooler(String s, boolean isDebug) {
			// HEX表示
			if (isDebug) {
				debugWriteSpooler.append(s);
			} else {
				writeSpooler.append(s);
			}
		}

		// スプーラーを介さず直接ファイルに書き込み
		public void writeDirect(String s, boolean isDebug) {
			// HEX表示
			try {
				if (!isDebug) {
					file = new File(outputPath);
					bw = new BufferedWriter(new FileWriter(file, true));
					bw.write(s);
					System.out.println(s);
					bw.newLine();
					bw.close();
				} else {
					file = new File(debugOutputPath);
					bw = new BufferedWriter(new FileWriter(file, true));
					bw.write(s);
					bw.newLine();
					bw.close();
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

	// byte[]→Hexへの変換
	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	public static String bytesToHex(byte b) {
		byte[] bytes = { b };
		return bytesToHex(bytes);
	}

	// スプーラーからファイル書き込み
	public void outPutFile() {
		try {
			if (!(writeSpooler.length() <= 1)) {
				file = new File(outputPath);
				bw = new BufferedWriter(new FileWriter(file, true));
				bw.write(writeSpooler.toString());
				System.out.println(writeSpooler.toString());
				bw.newLine();
				bw.close();
				writeSpooler.delete(0, writeSpooler.length());
			}
			if (debug) {
				if (!(debugWriteSpooler.length() <= 1)) {
					file = new File(debugOutputPath);
					bw = new BufferedWriter(new FileWriter(file, true));
					bw.write(debugWriteSpooler.toString());
					bw.newLine();
					bw.close();
					writeSpooler.delete(0, debugWriteSpooler.length());
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private long start, stop;

	@Override
	public void run() {
		// TODO Auto-generated method stub
		while (true) {
			try {
				// 定期的にファイルに書き込む
				// start = System.currentTimeMillis();
				outPutFile();
				// stop = System.currentTimeMillis();
				// System.out.println(stop - start);
				Thread.sleep(1000 / 30);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
}
