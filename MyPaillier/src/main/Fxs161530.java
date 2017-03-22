/**
 * Implementation of Paillier Cyptosystem toolbox
 * Author : Falak Singhal (fxs161530@utdallas.edu)
 * University of Texas at Dallas
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


public class Fxs161530 {

	public static void main(String[] args) {

		String options[]=args;
		Random seed=new Random();

		if(args.length==0) {
			System.out.println("No Arguments Provided, Exiting");
			System.exit(0);
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

					BigInteger n = new BigInteger(PUKeyN);
					BigInteger g = new BigInteger(PUKeyG);				

					//construt a PU key from (n,g)
					PaillierKey paillierPUKey = new PaillierKey(n, seed.nextLong());

					//setting up encryption environment
					Paillier paillier = new Paillier();
					paillier.setEncryption(paillierPUKey);

					BigInteger data,dataSquare,eData,eDataSquare;
					Iterator<Integer> iterator = dataList.iterator();

					while(iterator.hasNext()){

						data =BigInteger.valueOf((long)iterator.next().intValue());
						dataSquare=BigInteger.valueOf((long)iterator.next().intValue());
						eData = paillier.encrypt(data);
						eDataSquare= paillier.encrypt(dataSquare);

						fileWriter.write(eData.toString());
						fileWriter.write(",");
						fileWriter.write(eDataSquare.toString()+"\n");

					}

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
						}

						while(iteratorXSquare.hasNext()){
							BigInteger xSqVal=iteratorXSquare.next();
							eSumXSquare=paillier.add(eSumXSquare, xSqVal);
						}

						BigInteger numberOfRecords = BigInteger.valueOf(encryptedX.size());
						BigInteger eNumberOfRecords=paillier.encrypt(numberOfRecords);

						fileWriter.write(eSumX.toString()+"\n");
						fileWriter.write(eSumXSquare.toString()+"\n");
						fileWriter.write(eNumberOfRecords.toString());

						inputFileScanner.close();
						fileWriter.close();
						keyFileScanner.close();
						System.out.print("Success");
					}

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

					System.out.println("Scanned N :"+keyN);
					System.out.println("Scanned D :"+PrKeyD);

					BigInteger n = new BigInteger(keyN);
					BigInteger d = new BigInteger(PrKeyD);

					PaillierPrivateKey paillierPrivateKey=new PaillierPrivateKey(n, d, seed.nextLong());
					Paillier paillier = new Paillier(paillierPrivateKey);


					//read the encrypted file and use above Paillier PR key to decrypt.

					BigInteger eInputData,dData;
					while(eInputFileScanner.hasNextLine()){

						eInputData=new BigInteger(eInputFileScanner.nextLine().toString());
						System.out.println("Read eInput :"+eInputData);

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
