package com.codyy.coco.mina;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.util.Scanner;

import javax.management.RuntimeErrorException;

import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;

public class JudgeInitStartUpInfo implements ApplicationListener<ContextRefreshedEvent> {
	
	private static final char[] HEX = { '0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };


	@Override
	public void onApplicationEvent(ContextRefreshedEvent event) {
		// 需要执行的逻辑代码，当spring容器初始化完成后就会执行该方法。
		String zbInfo = getZbInfo().trim();
		String cpuInfo ="";
		try {
			cpuInfo = getCpuInfo().trim();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		String ypInfo = getYpInfo();
		String key = encode(zbInfo.concat(cpuInfo).concat(ypInfo)
				.concat("coco_codyy"));
//		System.out.println("coco_key==="+key);
//		System.out.println(this.getClass().getClassLoader().getResource("").getPath()+"coco_key.txt");
		File file = new File(this.getClass().getClassLoader().getResource("").getPath()+"coco_key.txt");
		String str = "";
		try {
			String encoding = "GBK";
			if (file.isFile() && file.exists()) { // 判断文件是否存在
				InputStreamReader read = new InputStreamReader(new FileInputStream(file), encoding);// 考虑到编码格式
				BufferedReader bufferedReader = new BufferedReader(read);
				String lineTxt = null;
				while ((lineTxt = bufferedReader.readLine()) != null) {
					str+=lineTxt;
				}
				read.close();
			} else {
				System.out.println("找不到指定的文件");
			}
		} catch (Exception e) {
			System.out.println("读取文件内容出错");
			e.printStackTrace();
		}
//		System.out.println("coco_readfile==="+str);

		if(!key.equals(str)){
			throw new RuntimeErrorException(null, "服务器没有授权");
		}

	}
	
	/**
	 * 获取操作系统
	 * @return
	 */
	public static String getOsName() {
		String os = "";
		os = System.getProperty("os.name");
		return os;
	}

	public static String isSCSIorIDEHD() {
		String os = getOsName();
		if (os.startsWith("Linux")) {
			// ubuntu系统下确定有root权限
			String command = "fdisk -l";
			Process p;
			try {
				p = Runtime.getRuntime().exec(command);
				BufferedReader br = new BufferedReader(new InputStreamReader(
						p.getInputStream()));
				String line;
				while ((line = br.readLine()) != null) {
					if (line.contains("sd")) {
						return "scsi";
					}
					if (line.contains("hd")) {
						return "ide";
					}
				}
				br.close();
			} catch (IOException e) {
			}
		}
		return "unkonwn"; // 未知类型
	}

	/**
	 * 获取硬盘序列号（Windows && Linux）
	 * @return
	 */
	public static String getYpInfo() {

		String sn = "";
		String os = getOsName();
		if (os.startsWith("Linux")) {
			if (isSCSIorIDEHD() == "scsi") {
				// 注意如果是ubuntu等系统用户，本身没有root权限，请先：chmod 777 /dev/sda
				String command = "hdparm -i /dev/sda";
				Process p;
				try {
					p = Runtime.getRuntime().exec(command);
					BufferedReader br = new BufferedReader(
							new InputStreamReader(p.getInputStream()));
					String line;
					while ((line = br.readLine()) != null) {
						if (line.contains("Serial Number")) {
							int index = line.indexOf("Serial Number")
									+ "Serial Number".length() + 1;
							sn = line.substring(index);
							break;
						}
					}
					br.close();
				} catch (IOException e) {
				}
			} else if (isSCSIorIDEHD() == "ide") {
				// 注意如果是ubuntu等系统用户，本身没有root权限，请先：chmod 777 /dev/sda
				String command = "hdparm -i /dev/hda";
				Process p;
				try {
					p = Runtime.getRuntime().exec(command);
					BufferedReader br = new BufferedReader(
							new InputStreamReader(p.getInputStream()));
					String line;
					while ((line = br.readLine()) != null) {
						if (line.contains("Serial Number")) {
							int index = line.indexOf("Serial Number")
									+ "Serial Number".length() + 1;
							sn = line.substring(index);
							break;
						}
					}
					br.close();
				} catch (IOException e) {
				}
			} else {
				sn = "unknown";
			}

		}else if(os.startsWith("Windows")){
			sn=getYpSerialNumber("C");
		}
		sn = sn.trim();
//		System.out.println("硬盘序列号："+sn);
		return sn;
	}

	/**
	 * 获取硬盘序列号（Windows）
	 * 
	 * @param drive
	 * @return
	 */
	public static String getYpSerialNumber(String drive) {
		String result = "";
		try {
			File file = File.createTempFile("realhowto", ".vbs");
			file.deleteOnExit();
			FileWriter fw = new java.io.FileWriter(file);
			String vbs = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\n"
					+ "Set colDrives = objFSO.Drives\n"
					+ "Set objDrive = colDrives.item(\""
					+ drive
					+ "\")\n"
					+ "Wscript.Echo objDrive.SerialNumber"; // see note
			fw.write(vbs);
			fw.close();
			Process p = Runtime.getRuntime().exec(
					"cscript //NoLogo " + file.getPath());
			BufferedReader input = new BufferedReader(new InputStreamReader(
					p.getInputStream()));
			String line;
			while ((line = input.readLine()) != null) {
				result += line;
			}
			input.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result.trim();
	}
	
	/**
	 * 获取cpu信息（Windows&&Linux）
	 * @return
	 * @throws IOException
	 */
	public static String getCpuInfo() throws IOException{
		String sn = "";
		String os = getOsName();
		if(os.startsWith("Linux")){
			String command = " dmidecode -t 4 ";
			Process p;
			try {
				p = Runtime.getRuntime().exec(command);
				BufferedReader br = new BufferedReader(
						new InputStreamReader(p.getInputStream()));
				String line;
				while ((line = br.readLine()) != null) {
					if (line.contains("Serial Number")) {
						int index = line.indexOf("Serial Number")
								+ "Serial Number".length() + 1;
						sn = line.substring(index);
						break;
					}
				}
				br.close();
			} catch (IOException e) {
			}
//			System.out.println("Linux:cpu Serial Number："+sn);
		}else if(os.startsWith("Windows")){
			sn=cpu().trim();
		}
		
		return sn;
	}

	/**
	 * 获取cpu序列号（Windows）
	 * 
	 * @return
	 * @throws IOException
	 */
	public static String cpu() throws IOException {
		// long start = System.currentTimeMillis();
		Process process = Runtime.getRuntime().exec(
				new String[] { "wmic", "cpu", "get", "ProcessorId" });
		process.getOutputStream().close();
		Scanner sc = new Scanner(process.getInputStream());
		String property = sc.next();
		String serial = sc.next();
		return serial;
	}
	
	/**
	 * 获取主板序列号（windows&&linux）
	 * @return
	 */
	public static String getZbInfo(){
		String sn = "";
		String os = getOsName();
		if(os.startsWith("Linux")){
			String command = "dmidecode -t 1";
			Process p;
			try {
				p = Runtime.getRuntime().exec(command);
				BufferedReader br = new BufferedReader(
						new InputStreamReader(p.getInputStream()));
				String line;
				while ((line = br.readLine()) != null) {
					if (line.contains("Serial Number")) {
						int index = line.indexOf("Serial Number")
								+ "Serial Number".length() + 1;
						sn = line.substring(index);
						break;
					}
				}
				br.close();
			} catch (IOException e) {
			}
			System.out.println("Linux:主板序列号："+sn);
		}else if(os.startsWith("Windows")){
			sn=getMotherboardSN().trim();
		}
		
		return sn;
	}

	/**
	 * 获取主板序列号
	 * 
	 * @return
	 */
	public static String getMotherboardSN() {
		String result = "";
		try {
			File file = File.createTempFile("realhowto", ".vbs");
			file.deleteOnExit();
			FileWriter fw = new java.io.FileWriter(file);
			String vbs = "Set objWMIService = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")\n"
					+ "Set colItems = objWMIService.ExecQuery _ \n"
					+ "   (\"Select * from Win32_BaseBoard\") \n"
					+ "For Each objItem in colItems \n"
					+ "    Wscript.Echo objItem.SerialNumber \n"
					+ "    exit for  ' do the first cpu only! \n" + "Next \n";
			fw.write(vbs);
			fw.close();
			Process p = Runtime.getRuntime().exec(
					"cscript //NoLogo " + file.getPath());
			BufferedReader input = new BufferedReader(new InputStreamReader(
					p.getInputStream()));
			String line;
			while ((line = input.readLine()) != null) {
				result += line;
			}
			input.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result.trim();
	}


	public static final String encode(String source) {
		try {
			byte[] sourceBytes = source.getBytes();
			MessageDigest mdInst = MessageDigest.getInstance("MD5");
			mdInst.update(sourceBytes);
			byte[] md = mdInst.digest();
			int j = md.length;
			char str[] = new char[j * 2];
			int k = 0;
			for (int i = 0; i < j; i++) {
				str[k++] = HEX[md[i] >>> 4 & 0xf];
				str[k++] = HEX[md[i] & 0xf];
			}
			return new String(str);
		} catch (Exception e) {
			return null;
		}
	}
}