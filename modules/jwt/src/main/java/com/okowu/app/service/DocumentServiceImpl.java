package com.okowu.app.service;

import com.okowu.app.db.DocumentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DocumentServiceImpl {

  private final DocumentRepository documentRepository;
}
