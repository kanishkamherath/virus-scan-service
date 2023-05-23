package com.kanishka.clamav.service;

import java.io.IOException;
import java.io.InputStream;

import com.kanishka.clamav.dto.VirusScanResult;

public interface ClamAVService {

	boolean ping();
	
	VirusScanResult scan(InputStream inputStream) throws IOException;

}
