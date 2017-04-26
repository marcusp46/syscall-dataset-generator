import java.util.Timer;
import java.util.TimerTask;
import java.lang.ProcessBuilder;
import java.io.IOException;
import java.io.FileReader;
import java.io.File;
import java.util.Queue;
import java.util.Date;
import java.util.Formatter;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.io.BufferedReader;
import java.lang.Runnable;
import java.lang.StringBuilder;

class docker_crawler{

	public static String id_generate()
	{
		//1652961251_28022017_205816
//			10 digits, 2 day, 2 month, 4 year, 2 hour, 2 min, 2 sec
		StringBuilder sb = new StringBuilder();
		Formatter formatter = new Formatter(sb,java.util.Locale.US);
		String uid = new String();
		long time = System.currentTimeMillis();
		Date date = new Date(time);
		int rand = java.lang.Math.abs(new java.util.Random(time).nextInt());

		formatter.format("%010d_%td%tm%tY_%tH%tM%tS",rand,date,date,date,date,date,date);


		return formatter.toString();
	}


	public static void main(String args[])
	{
//		Timer visitTimer[]/* = new Timer()*/;
		int numUrls = 0, batch = 100;
		FileReader urlFile = null;
		BufferedReader urlFileBuffered;
//		Queue<String> visitQueue = new Queue<String>();
		ConcurrentLinkedQueue<String>[] visitQueue;
		Thread[] visitThread;

		if(args.length < 1)
		{
			System.out.println("URL file not specified\n");
			System.exit(1);
		}

		if(args.length == 2)
			batch = Integer.parseInt(args[1]);

		try{
		urlFile = new FileReader(args[0]);
		}catch(IOException e)
		{
			System.out.println("Error opening URL file\n");
			System.exit(1);
		}

		System.out.println("File = " + args[0] + " batch = " + batch + "\n");

//		visitTimer = new Timer[batch];
		visitQueue = new ConcurrentLinkedQueue[batch];
		visitThread = new Thread[batch];
//		for(int i=0;i<batch;i++)
//			visitTimer[i] = new Timer();
		for(int i=0;i<batch;i++)
			visitQueue[i] = new ConcurrentLinkedQueue<String>();

//		System.out.println(args.length + " arguments\n");

		//read URLS
		urlFileBuffered = new BufferedReader(urlFile);

		//for each URL, schedule visit...stagger? 100 at a time
		int i_assign = 0;
		while(true)
		{
			String tmp = null;
			try{
			tmp = urlFileBuffered.readLine();
			}
			catch(IOException e)
			{
				System.out.println("Error reading file\n");
				System.exit(1);
			}
			if(tmp == null)
				break;
			numUrls++;
//			visitTimer.schedule
//			System.out.println(tmp);
			if(i_assign >= batch)
				i_assign = 0;

			visitQueue[i_assign++].add(tmp);
		}

		System.out.println(numUrls + " urls read\n");

		int tnumUrls = numUrls;

//		while(visitQueue.size() > 0)
//		{
		try{
			for(int i=0;i<batch;i++)
			{
//				visitTimer[i].schedule(new visitTask(visitQueue.remove(),1),0);
				System.out.println("Starting thread " + (i+1) + ", queue size=" + visitQueue[i].size() + "\n");
				visitThread[i] = new Thread(new visitTask(visitQueue[i],1,i));
//				Thread.sleep(10000 * i);
				visitThread[i].start();
			
			}
			for(int i=0;i<batch;i++)
			{
				visitThread[i].join();
			}
		}catch(InterruptedException e){
			System.out.println("Problem with thread pool\n");
			System.exit(1);
		}
//		}
	

		System.exit(1);
//		visitTimer.cancel();
	}

}

class visitTask implements Runnable
{
//	String visitUrl;
	int visitTime,threadID;
	ProcessBuilder pb;

	ConcurrentLinkedQueue<String> visitQueue;
	private Process visitProcess;

	public visitTask(String url, int time, int tid)
	{
		visitQueue = new ConcurrentLinkedQueue<String>();
		visitQueue.add(url);
//		visitUrl = url;
		visitTime = time;
		threadID = tid;
	}

	public visitTask(ConcurrentLinkedQueue<String> queue, int time, int tid)
	{
		visitQueue = queue;
		
//		visitUrl = null;
		visitTime = time;
		threadID = tid;
	}

	public void run()
	{
		//visit page visit script
		while(visitQueue.size() > 0)
		{
			String u = visitQueue.remove();
			String uid = docker_crawler.id_generate();
			long start_time, end_time;

			pb = new ProcessBuilder("/bin/bash","./container_visit.sh",u,String.valueOf(threadID),uid);
			pb.redirectOutput(ProcessBuilder.Redirect.appendTo(new File("deleteme.out")));
			pb.redirectError(ProcessBuilder.Redirect.appendTo(new File("deleteme_error.out")));

			java.util.List<String> cmdLine = pb.command();

			String scmdLine = new String("");

			for(int i=0;i < cmdLine.size();i++)
			{
				scmdLine += cmdLine.get(i) + " ";
			}
			System.out.print(scmdLine);
			System.out.println();

			while(true)
			{
				start_time = System.currentTimeMillis();

				try{
				visitProcess = pb.start();
				}catch(IOException e)
				{
					System.out.println("Problem executing script\n");
					System.exit(1);
				}

				try{
				visitProcess.waitFor();
				}catch(InterruptedException e)
				{
					System.out.println("Problem with scheduling visit\n");
					System.exit(1);
				}
				end_time = System.currentTimeMillis();

				double elapse_time = (double)(end_time - start_time) / 1000.0;

				System.out.println("Exit = " + visitProcess.exitValue() + " Time elapsed is " + elapse_time + ", ThreadID is " + threadID);
				if(elapse_time < 180)
					System.out.println("RETRY: Error in visit, ThreadID is " + threadID);
				else 
					break;
			}

			System.out.println("Thread " + threadID + " ," + visitQueue.size() + " remaining");	
		}
	}

}
