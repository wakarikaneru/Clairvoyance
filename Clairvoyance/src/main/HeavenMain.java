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
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;//パケットクラス
import org.jnetpcap.packet.PcapPacketHandler;//パケットハンドラクラス
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * RigidChips用パケットキャプチャ+解析+RCとの通信ツール オンラインの他プレイヤーが撃ったARM弾の情報をRCに送信します
 *
 */
public class HeavenMain {
	private static final String PROPERTIES = "properties.xml";// プロパティファイルのパス
	private static final String STARTUP_MESSAGE = "Heaven Standby";// 起動時に表示されるメッセージ

	private static final String PACKET_MODELDATA = "3D";// モデル情報送信パケットの識別子？[16進]
	private static final String PACKET_MODELDATA_FLAGSTART = "15";// モデル情報送信パケットの識別子？フラグメントされた場合のスタート[16進]
	private static final String PACKET_MODELDATA_FLAG = "2D";// モデル情報送信パケットの識別子？フラグメントされた場合の2番目以降[16進]
	private static final String PACKET_LIVE = "80";// 生存情報送信パケットの識別子？[16進]
	private static final String PACKET_BULLET = "15";// ARM弾の識別子？[16進]
	private static final String PACKET_BULLET_FLAG = "25";// ARM弾の識別子？[16進]
	private static final int BULLET_SIZE = 52; // ARM弾1発分のデータのサイズ[バイト]

	private Properties prop = new Properties();
	private String outputPath = "";
	private String address = "";
	private int port = 0;
	private boolean debug = false;
	private String debugOutputPath = "";

	private File file = null;
	private BufferedWriter bw = null;

	private PcapHeader hdr = null;
	private JBuffer buf = null;

	private int id = 0;

	private Udp udp = new Udp();
	private PcapPacket packet = null;

	private byte[] b = null;
	private ByteBuffer bb = null;

	public static void main(String[] args) {
		HeavenMain main = new HeavenMain();
		main.capture();
	}

	public HeavenMain() {
	}

	public void capture() {
		System.out.println(STARTUP_MESSAGE);
		// プロパティ読み込み
		System.out.println("Loading Property:");
		try {
			loadProperty();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		// プロパティ表示
		System.out.println("\tOutput Path\t" + outputPath);
		System.out.println("\tIP Address\t" + address);
		System.out.println("\tPort\t" + port);
		System.out.println("\tDebug\t" + debug);
		System.out.println("\tDebug Output Path\t" + debugOutputPath);

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

		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		PcapIf device = null;

		try {
			device = alldevs.get(Integer.parseInt(br.readLine()));
		} catch (NumberFormatException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		if (device == null) {
			device = alldevs.get(0);
		}

		System.out.printf("\nChoosing '%s' on your behalf:\n",
				(device.getDescription() != null) ? device.getDescription()
						: device.getName());

		// キャプチャ準備
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		// int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int flags = Pcap.MODE_NON_PROMISCUOUS;
		int timeout = 15; // millis
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout,
				errbuf);

		// 準備中にエラーが発生したら終了
		if (pcap == null) {
			System.err.printf("Error while opening device for capture: %s\n",
					errbuf.toString());
			return;
		}

		// キャプチャフィルタ設定
		PcapBpfProgram program = new PcapBpfProgram();
		String expression = "ip and udp and dst host " + address
				+ " and dst port " + port;
		int optimize = 1; // 0 = false
		int netmask = 0xFFFFFF00; // 255.255.255.0

		// キャプチャフィルタをコンパイル
		if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {
			System.err.println(pcap.getErr());
			return;
		}

		// キャプチャフィルタを適用
		if (pcap.setFilter(program) != Pcap.OK) {
			System.err.println(pcap.getErr());
			return;
		}

		// キャプチャ開始
		hdr = new PcapHeader(JMemory.POINTER);
		buf = new JBuffer(JMemory.POINTER);
		id = JRegistry.mapDLTToId(pcap.datalink());

		// パケットをキャプチャし続ける
		try {
			while (true) {
				while (pcap.nextEx(hdr, buf) == Pcap.NEXT_EX_OK) {
					// パケットのキャプチャに成功したら
					packet = new PcapPacket(hdr, buf);
					packet.scan(id);

					// パケットはUDPか
					if (packet.hasHeader(udp)) {
						// パケットをUDPとして解析
						packet.scan(Udp.ID);
						// パケットのデータ部分を抽出
						b = udp.getPayload();

						// モデルデータの通信か判別する
						if (PACKET_MODELDATA.equals(bytesToHex(b[0]))
								|| PACKET_MODELDATA_FLAGSTART
										.equals(bytesToHex(b[0]))) {
							// ARM弾の射撃情報か判別する
							if (PACKET_BULLET.equals(bytesToHex(b[4]))) {
								// データの解析
								decodeData(b, 6);
								System.out.println(((b.length - 6) / 52)
										+ " Bullet(s) Detected");
							}
						}
						// フラグメントされた途中のパケットか判別する
						if (PACKET_MODELDATA_FLAG.equals(bytesToHex(b[0]))) {
							// ARM弾の射撃情報か判別する?(謎多し)
							if (PACKET_BULLET_FLAG.equals(bytesToHex(b[4]))) {
								// データの解析
								decodeData(b, 2);
								System.out.println(((b.length - 2) / 52)
										+ " Bullet(s) Detected?");
							}
						}
						// デバッグモード
						if (debug) {
							outputHex(b);
						}
					}
				}
			}
		} finally {
			pcap.close();
		}
	}

	/**
	 * プロパティを読み込むメソッド
	 * 
	 * @throws IOException
	 */
	private void loadProperty() throws IOException {
		InputStream is = new FileInputStream(PROPERTIES);
		prop.loadFromXML(is);

		outputPath = prop.getProperty("outputPath");
		address = prop.getProperty("IPAddress");
		port = Integer.parseInt(prop.getProperty("port"));
		debug = Boolean.parseBoolean(prop.getProperty("debug"));
		debugOutputPath = prop.getProperty("debugOutputPath");
	}

	// 抽出したデータ部を解析して出力する
	private void decodeData(byte[] b, int headerBytes) {
		bb = ByteBuffer.wrap(b);
		bb.order(ByteOrder.LITTLE_ENDIAN);
		// データを読み込む準備
		try {
			// ヘッダ部分を読み飛ばす
			for (int i = 0; i < headerBytes; i++) {
				bb.get();
			}
			// データを読み込む
			StringBuilder str = new StringBuilder();
			for (int i = 0; i < (b.length - headerBytes) / BULLET_SIZE; i++) {
				str.append("{");
				// データを抽出
				str.append("x=" + bb.getFloat() + ",");
				str.append("y=" + bb.getFloat() + ",");
				str.append("z=" + bb.getFloat() + ",");
				str.append("vx=" + bb.getFloat() + ",");
				str.append("vy=" + bb.getFloat() + ",");
				str.append("vz=" + bb.getFloat() + ",");
				str.append("option=" + bb.getFloat());
				bb.getFloat(); // 用途不明 読み出しはするけど利用はしない
				bb.getFloat();
				bb.getFloat();
				bb.getFloat();
				bb.getFloat();
				bb.getFloat();
				str.append("};");
			}
			// writeSpooler(str.toString(), false);
			writeFile(str.toString(), false);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// デバッグ用
	// HEXを出力する
	public void outputHex(byte[] b) {
		// writeSpooler(bytesToHex(b), true);
		writeFile(bytesToHex(b), true);
	}

	// 直接ファイルに書き込み
	private void writeFile(String s, boolean isDebug) {
		// HEX表示
		try {
			if (!isDebug) {
				file = new File(outputPath);
				bw = new BufferedWriter(new FileWriter(file, true));
				bw.write(s);
				// System.out.println(s);
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
			e.printStackTrace();
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

}
