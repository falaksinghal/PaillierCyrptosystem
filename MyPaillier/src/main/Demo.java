/**
 * Implementation of Paillier Cyptosystem toolbox
 * Author : Falak Singhal (fxs161530@utdallas.edu)
 * University of Texas at Dallas
 * 
 * Using the Paillier encryption toolbox1, develop a simple program that executes the following
 * tasks given the following command line options:
 * • -keygen -outputPK public-key-file -outputPr private-key-file: It will generate Paillier with
 * n equals to 2048 bit key. Output two files, one public key, one private key file. To enable
 * this, you may need to change the constructor of the Pallier class. By default,
 * it may not allow you to do this. Please take a look at the code. Please
 * include the modified Paillier toolbox code in your submission.
 * • -encrypt -pk public-keyfile -input input-file -output output-file: It will create an encrypted
 * file that contains two encrypted values per line for each integer per line in the input file,
 * for example, if x is on the first line of the input file, the first line of the output file will
 * contain E(x), E(x^2).
 * • -process -pk public-key-file -input encrypted-file -output output-file: You will process the
 * encrypted file with two encrypted values per line to output, encrypted sum, encrypted
 * sum of squares and encrypted count values. Each of these encrypted statistics must be
 * outputed on a separate line.
 * • -decryt -pr private-key-file -input encrypted-input-file -output output-file This will be
 * used to decrypt the encrypted values stored per line in the file to get the decrypted
 * results.
 * 
 */

package main;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

import paillierp.Paillier;
import paillierp.key.KeyGen;
import paillierp.key.PaillierKey;
import paillierp.key.PaillierPrivateKey;


public class Demo {

	public static void main(String[] args) {

		String options[]=args;
		Random seed=new Random();

		//test Code
		if(args.length==0) {
			// option 4 decryption code -	

			//	BigInteger keyLength=new BigInteger(128, seed);

			int keylen=2048;

			//	PaillierKey paillierKey=new PaillierKey(keyLength, seed.nextLong());
			//	System.out.println(paillierKey.canEncrypt());

			PaillierPrivateKey alicePrivateKey=KeyGen.PaillierKey(keylen, seed.nextLong());
			PaillierPrivateKey bobPrivateKey = KeyGen.PaillierKey(keylen, seed.nextLong());

			//System.out.println(alicePrivateKey.canEncrypt());

			//PaillierKey paillierPublicKey=paillierPrivateKey.getPublicKey();

			Paillier alicePUKey=new Paillier(alicePrivateKey.getPublicKey());
			Paillier bobPUKey= new Paillier(bobPrivateKey.getPublicKey());

			BigInteger plainText1=BigInteger.valueOf(8);
			BigInteger plainText2 = BigInteger.valueOf(5);

			//Alice sends plainText to Bob Encrypted as cryptext using bob's public key

			BigInteger cryptext1=bobPUKey.encrypt(plainText1);
			BigInteger cryptext2 = bobPUKey.encrypt(plainText2);

			BigInteger sumOfCryptText = bobPUKey.add(cryptext1,cryptext2);

			//BigInteger crpt=paillierp.Paillier.encrypt(plainText, paillierPublicKey);
			//System.out.println(crpt.intValue());

			System.out.println("Alice sends "+plainText1+" to Bob as "+cryptext1);

			//System.out.println(plainText);

			bobPUKey.setDecryption(bobPrivateKey);

			BigInteger bobMsg= bobPUKey.decrypt(cryptext1);


			BigInteger decryptedSum = bobPUKey.decrypt(sumOfCryptText);

			System.out.println(decryptedSum);


			System.out.println(bobMsg);		
		}

		//Funtionality 1 -keygen -outputPK public-key-file -outputPr private-key-file

		else if(options[0].equalsIgnoreCase("-keygen")){
			if(options[1].equalsIgnoreCase("-outputPK") && options[3].equalsIgnoreCase("-outputPr")){


				String publicKeyFilePath=options[2];
				String privateKeyFilePath=options[4];

				FileWriter fileWriterPK=null, fileWriterPr=null;
				BufferedWriter bufferedWriterPK=null, bufferedWriterPr=null;


				int keylen=2048;
				PaillierPrivateKey privateKey=KeyGen.PaillierKey(keylen, seed.nextLong());
				PaillierKey publicKey = privateKey.getPublicKey();

				//Public Key (n,g) ; g = n+1 for simplicity
				//Private Key (n, d) 
				BigInteger n,d,nPlusOne;

				n=privateKey.getN();
				nPlusOne=publicKey.getNPlusOne();
				d=privateKey.getD();
				

				try{

					fileWriterPK = new FileWriter(publicKeyFilePath);
					fileWriterPr = new FileWriter(privateKeyFilePath);

					bufferedWriterPK = new BufferedWriter(fileWriterPK);
					bufferedWriterPr = new BufferedWriter(fileWriterPr);

					bufferedWriterPK.write(n+" "+nPlusOne);
					bufferedWriterPr.write(n+" "+d);

					bufferedWriterPK.close();
					bufferedWriterPr.close();
					System.out.println("Success");			
				}
				catch (Exception e) {
					System.out.println("Exception While Generating Keys-");
					e.printStackTrace();
				}	

			}
		}

		//option 2 -encrypt -pk public-keyfile -input input-file -output output-file
		else if(options[0].equalsIgnoreCase("-encrypt")){
			if(options[1].equalsIgnoreCase("-pk") && options[3].equalsIgnoreCase("-input") && options[5].equalsIgnoreCase("-output")){

				File publicKeyFile = new File(options[2]);
				File inputFile = new File(options[4]);
				File outputFile = new File(options[6]);

				try{

					Scanner keyFileScanner=new Scanner(publicKeyFile);
					Scanner inputFileScanner = new Scanner(inputFile);
					FileWriter fileWriter = new FileWriter(outputFile);

					StringBuilder publicKeyString=new StringBuilder();
					while(keyFileScanner.hasNextLine()){
						publicKeyString.append(keyFileScanner.nextLine()+" ");
					}

					//constructing Keys	
					String [] PUKey = publicKeyString.toString().split(" ");
					String PUKeyN = PUKey[0];
					String PUKeyG = PUKey[1];
					
					//get all the input numbers and add them to a List
					int temp=0;
					List<Integer> dataList=new ArrayList<Integer>();	
					while(inputFileScanner.hasNextLine()){
						temp=Integer.parseInt(inputFileScanner.nextLine());
						dataList.add(new Integer(temp));
						
						// add the square of the number to be encrypted later 
						temp*=temp;
						dataList.add(new Integer(temp));
					}
					
				/*	for(Integer data:dataList){
						System.out.println(data.intValue());
					}*/
					

					BigInteger n = new BigInteger(PUKeyN);
					BigInteger g = new BigInteger(PUKeyG);

					/*					String inputDigitString[]= inputDigits.toString().split("\n");
					int [] inputData = new int[inputDigits.length()];
					int index=0;
					for(String data:inputDigitString){
						System.out.println(data);
						inputData[index]= Integer.parseInt(data);
					}

					for(int i=0;i<inputData.length;i++){
						System.out.println(inputData[i]);
					}

					 */					

					//construt a PU key from (n,g)
					PaillierKey paillierPUKey = new PaillierKey(n, seed.nextLong());
					
					//setting up encryption environment
					Paillier paillier = new Paillier();
					paillier.setEncryption(paillierPUKey);

					BigInteger data,dataSquare,eData,eDataSquare;
					Iterator<Integer> iterator = dataList.iterator();

					while(iterator.hasNext()){

						data =BigInteger.valueOf((long)iterator.next().intValue());
						
						//System.out.println("ln 196 Got Data :"+data.intValue());
						
						dataSquare=BigInteger.valueOf((long)iterator.next().intValue());
						//System.out.println("ln 198 Got DataSquare :"+dataSquare.intValue());
						
						//encrypt the data and write to the file
						eData = paillier.encrypt(data);
						eDataSquare= paillier.encrypt(dataSquare);

						fileWriter.write(eData.toString());
						fileWriter.write(",");
						fileWriter.write(eDataSquare.toString()+"\n");
						
					}
		/*			

					//TestCode-----------------------------------
					String PRKeyTest = "106702112431585138293918703532328324636955749607560715035855675147947540301206526112831708527840421323839147367962478628054115338876577651437919539289976763682296343517076016422086013883004832910811031573582943129786092085834879113173573097410954024965847515327256481056414653259186495831449305192617812684254664369169629891725957088794787215352962158415896916588638441096482491927917890593356022126727765783031757884047527194519571704117522522678773810150772385006620945851813130976806731960006671747551808345281584381559124645102176830100858763248056424256856445236387256960286000732837364846978411584505249530436878150673962029136028916368168945002140794537053564002841262360224791001412643826085596174268913272235496496701530708139662390319761043519490951459579061187319369585646349662332064449507417135759371972679086053460158114820988939882161293893067049798189367893284425216338494575614311708910322563306106735257162793608628410513537269750739696578224505125639316224480761859638970420084321655692447786534087387099867356808341133882303610806287928679230676139352775046333425704809507353044384537718812315457640310889140636851429632817558844723918760308435523226228640062852804357416135537227168765952425610499166315637967032";
					BigInteger d = new BigInteger(PRKeyTest);

					PaillierPrivateKey testPRKey = new PaillierPrivateKey(n, d, seed.nextInt());

					//--------------------------------------


					//Create a PU key from n
					PaillierKey testPUKey = new PaillierKey(n, seed.nextLong());

					//Set up Encrp Decryp Environment
					Paillier paillierTest = new Paillier();

					paillierTest.setDecryption(testPRKey);
					paillierTest.setEncryption(testPUKey);

					//Test
					//System.out.println(PUKeyN);
					//System.out.println(testPUKey.getN());

					BigInteger testPlainText =BigInteger.valueOf(80);
					

					BigInteger testEcry = paillierTest.encrypt(testPlainText);

					System.out.println("Test Value "+testEcry.intValue());

					BigInteger testDecryp = paillierTest.decrypt(testEcry);
					System.out.println("Decriptefd "+testDecryp.intValue());

					String testSq="160497427813414091179470381418214077556849661220002336225276060926845326042109597475845508794641599819090090022834053012000625286279728932017277342393447717510296061240234688984459484653612790995528246383405103780652946742771537397502284366965744539577382379150035887193598018163106925563507266288766409376195711058272558155658255781711692205515466343127110273255489574304187081882781063663378843114008455203974362338374085395944774887870897866034590288276135811159182066776071728921132153862557638295380825126201067783691604475670175563216779082414445372806268553608898839557074839457839152704222673061332225206906750851717572708193778974071237127302643360431102859612502039400855165715171925712173885007045107774751141703260172742505656918637841232845149370163865455796566608396647706872279464652789321049507325073037321549518220279164259621770770280787948238520131801859356615610665103617111806362358807897260248241490638527683365750409386069866473833914301863861460889374680324520892661407359683734185140869281198315121994549547524699751318513384042792435708193633483774050857359004133440331710078430727119713165255323033912815248826369875035652731288320946253914500274635769146578352041981760812532146224488692238644920239060170437170991616981378431308845016608528424935446240375599794671865052013598811200861310852731781393014253322813788077116807312981646916229729399084137395482809738650524317939535530583329315247525935166538418563061311289761292083256709604493635086874136697168826410867830723183256878960187677555875896798552373502237729513473243574310001554620247639272579575207040490686867307236001837276882175040426770039711512181680136813482354074476605398204640217468828646248689462766731706839520363733984157758650482729489725022223304828009611225267317470670069333908539485603976475873712553350990780382375699695685746115331860942380324506900315734721181198198452415799832178524040581731465162485866645399893252152674467754991224923252322199018386658904896245915497966259654797607831458988701915860722761694023475353992594479978423674635858368022845754103117515813121942421350809314954989978054534320374786967098610206092182445363512029811976825059263211284639023127488436634620421380275069126062417714507702250565833705725764431310647041701720313133646476827232882800584975644035749486993866155745724410944350702146920964414488531405579569260861958529566811150727898370190253645230988113504741221382378434229419644771377927192679932342076475556046";
					BigInteger testDecryptionData = new BigInteger(testSq);
					System.out.println("Decrypted test Sq :"+paillierTest.decrypt(testDecryptionData).intValue());
					
					//-----------------------------------------------------------
			*/		
					inputFileScanner.close();
					keyFileScanner.close();
					fileWriter.close();
					System.out.println("Success");

				}catch (Exception e) {
					System.out.println("Exception While Encryption-");
					e.printStackTrace();
				}

			}
		}


		//option 3 -process -pk public-key-file -input encrypted-file -output output-file:
		else if(options[0].equalsIgnoreCase("-process")){
			if(options[1].equalsIgnoreCase("-pk") && options[3].equalsIgnoreCase("-input") && options[5].equalsIgnoreCase("-output")){

				List<String> inputCipherText=new ArrayList<String>();
				File publicKeyFile = new File(options[2]);
				File inputFile = new File(options[4]);
				File outputFile = new File(options[6]);
				
				List<BigInteger> encryptedX=new ArrayList<BigInteger>();
				List<BigInteger> encryptedXSquare=new ArrayList<BigInteger>();

				try{
					Scanner	inputFileScanner = new Scanner(inputFile);
					Scanner keyFileScanner=new Scanner(publicKeyFile);
					FileWriter fileWriter = new FileWriter(outputFile);


					while(inputFileScanner.hasNextLine()){
						inputCipherText.add(inputFileScanner.nextLine());
					}

					Iterator<String> cipherTextIterator=inputCipherText.iterator();
					String []eX_eXSquare=new String[2];
					while(cipherTextIterator.hasNext()){

						eX_eXSquare=cipherTextIterator.next().toString().split(",");

						encryptedX.add(new BigInteger(eX_eXSquare[0]));
						encryptedXSquare.add(new BigInteger(eX_eXSquare[1]));
						//System.out.println("XVal :"+eX_eXSquare[0]);
						//System.out.println("XSquareVal :"+eX_eXSquare[1]);


					}
					//					System.out.println(encryptedX.get(0));
					//	System.out.println(encryptedXsq.get(0));


					StringBuilder publicKeyString=new StringBuilder();
					while(keyFileScanner.hasNextLine()){
						publicKeyString.append(keyFileScanner.nextLine()+" ");
					}


					//constructing Keys	
					String [] PUKey = publicKeyString.toString().split(" ");
					String PUKeyN = PUKey[0];
					BigInteger n = new BigInteger(PUKeyN);

					PaillierKey paillierPUKey = new PaillierKey(n, seed.nextLong());
					
					//set up Encryption Environment
					Paillier paillier=new Paillier();
					paillier.setEncryption(paillierPUKey);

					Iterator<BigInteger> iteratorX=encryptedX.iterator();
					Iterator<BigInteger> iteratorXSquare=encryptedXSquare.iterator();

					//get first Values of X and XSquare in sum
					BigInteger eSumX=iteratorX.next();
					BigInteger eSumXSquare=iteratorXSquare.next();

					while(iteratorX.hasNext()){
						BigInteger xVal=iteratorX.next();
						eSumX=paillier.add(eSumX, xVal);
						//System.out.println("XVal During Summation "+xVal);
					}

					while(iteratorXSquare.hasNext()){
						BigInteger xSqVal=iteratorXSquare.next();
						eSumXSquare=paillier.add(eSumXSquare, xSqVal);
						//System.out.println("XSqVal During Summation"+xSqVal);
					}

					BigInteger numberOfRecords = BigInteger.valueOf(encryptedX.size());
					BigInteger eNumberOfRecords=paillier.encrypt(numberOfRecords);

					fileWriter.write(eSumX.toString()+"\n");
					fileWriter.write(eSumXSquare.toString()+"\n");
					fileWriter.write(eNumberOfRecords.toString());

					/*//----------------------------------------------------------
					//testing correctness of Encryption 

					String PRKeyD = "106702112431585138293918703532328324636955749607560715035855675147947540301206526112831708527840421323839147367962478628054115338876577651437919539289976763682296343517076016422086013883004832910811031573582943129786092085834879113173573097410954024965847515327256481056414653259186495831449305192617812684254664369169629891725957088794787215352962158415896916588638441096482491927917890593356022126727765783031757884047527194519571704117522522678773810150772385006620945851813130976806731960006671747551808345281584381559124645102176830100858763248056424256856445236387256960286000732837364846978411584505249530436878150673962029136028916368168945002140794537053564002841262360224791001412643826085596174268913272235496496701530708139662390319761043519490951459579061187319369585646349662332064449507417135759371972679086053460158114820988939882161293893067049798189367893284425216338494575614311708910322563306106735257162793608628410513537269750739696578224505125639316224480761859638970420084321655692447786534087387099867356808341133882303610806287928679230676139352775046333425704809507353044384537718812315457640310889140636851429632817558844723918760308435523226228640062852804357416135537227168765952425610499166315637967032";
					BigInteger d = new BigInteger(PRKeyD);

					PaillierPrivateKey testPRKey = new PaillierPrivateKey(n, d, seed.nextInt());

					paillier.setDecryption(testPRKey);

					BigInteger sumXD=paillier.decrypt(eSumX);

					paillier.setDecryption(testPRKey);
					
					System.out.println("eSumXSqs "+eSumXSquare);
					BigInteger sumXSqDcr=paillier.decrypt(eSumXSquare);
					
					System.out.println("SumX "+sumXD);

					System.out.println("SumXSq"+ sumXSqDcr);

					BigInteger count=paillier.decrypt(eNumberOfRecords);
					System.out.println("countD "+count);
					//----------------------------------------------------------
					*/
					
					inputFileScanner.close();
					fileWriter.close();
					keyFileScanner.close();
					System.out.print("Success");

				}catch (Exception e) {
					System.out.println("Exception During the processing-");
					e.printStackTrace();
				}

			}
		}

		//option 4 -decryt -pr private-key-file -input encrypted-input-file -output output-file

		else if(options[0].equalsIgnoreCase("-decryt")){
			if(options[1].equalsIgnoreCase("-pr") && options[3].equalsIgnoreCase("-input") && options[5].equalsIgnoreCase("-output")){

				File privateKeyFile = new File(options[2]);
				File eInputFile = new File(options[4]);
				File outputFile = new File(options[6]);

				try{
					Scanner keyFileScanner=new Scanner(privateKeyFile);
					Scanner eInputFileScanner = new Scanner(eInputFile);
					FileWriter fileWriter = new FileWriter(outputFile);
					
					StringBuilder privateKeyString=new StringBuilder();
					while(keyFileScanner.hasNextLine()){
						privateKeyString.append(keyFileScanner.nextLine()+" ");
					}
					
					//construct Paillier Private Key and setup Decryption Environment 
					String [] prKey = privateKeyString.toString().split(" ");
					String keyN = prKey[0];
					String PrKeyD = prKey[1];
					
					//System.out.println("Scanned N :"+keyN);
					//System.out.println("Scanned D :"+PrKeyD);

					BigInteger n = new BigInteger(keyN);
					BigInteger d = new BigInteger(PrKeyD);
					
					PaillierPrivateKey paillierPrivateKey=new PaillierPrivateKey(n, d, seed.nextLong());
					Paillier paillier = new Paillier(paillierPrivateKey);
					
					
					//read the encrypted file and use above Paillier PR key to decrypt.
					
					BigInteger eInputData,dData;
					while(eInputFileScanner.hasNextLine()){
						
						eInputData=new BigInteger(eInputFileScanner.nextLine().toString());
						//System.out.println("Read eInput :"+eInputData);
						
						dData = paillier.decrypt(eInputData);
						fileWriter.write(dData+"\n");
						
					}
						
					keyFileScanner.close();
					eInputFileScanner.close();
					fileWriter.close();
					System.out.println("Success");
				}catch (Exception e) {
					System.out.println("Exception While Decryption-");
					e.printStackTrace();
				}

			}
		}



	}
}
