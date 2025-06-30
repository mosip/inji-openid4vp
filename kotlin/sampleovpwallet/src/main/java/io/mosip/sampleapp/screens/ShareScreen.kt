package io.mosip.sampleapp.screens

import android.Manifest
import android.content.pm.PackageManager
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.OptIn
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.Button
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import androidx.navigation.NavController
import androidx.navigation.NavHostController
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import io.mosip.sampleapp.Constants
import io.mosip.sampleapp.utils.OpenID4VPManager
import io.mosip.sampleapp.data.SharedViewModel
import io.mosip.sampleapp.utils.MatchingVcsHelper
import io.mosip.sampleovpwallet.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors

@OptIn(ExperimentalGetImage::class)
@Composable
fun ShareScreen(navController: NavHostController, sharedViewModel: SharedViewModel) {
    val context = LocalContext.current

    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED
        )
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    when {
        hasCameraPermission -> {
            CameraPreviewAndScanner(sharedViewModel, navController)
        }
        else -> {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("Camera permission is required to scan QR codes")
                Spacer(modifier = Modifier.height(8.dp))
                Button(onClick = { permissionLauncher.launch(Manifest.permission.CAMERA) }) {
                    Text("Grant Permission")
                }
            }
        }
    }
}


@OptIn(ExperimentalGetImage::class)
@Composable
fun CameraPreviewAndScanner(
    sharedViewModel: SharedViewModel,
    navController: NavHostController
) {
    val context = LocalContext.current
    val cameraProviderFuture = remember { ProcessCameraProvider.getInstance(context) }
    val executor = remember { Executors.newSingleThreadExecutor() }

    var scannedText by remember { mutableStateOf<String?>(null) }
    var showErrorDialog by remember { mutableStateOf(false) }
    var scanningEnabled by remember { mutableStateOf(true) }

    LaunchedEffect(scannedText) {
        scannedText?.let {
            handleScannedText(
                urlEncodedAuthRequest = it,
                sharedViewModel = sharedViewModel,
                navController = navController,
                showError = { showErrorDialog = true },
                disableScanning = { scanningEnabled = false }
            )
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {

        AndroidView(factory = { ctx ->
            val previewView = androidx.camera.view.PreviewView(ctx)

            val cameraProvider = cameraProviderFuture.get()
            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }

            val barcodeScanner = BarcodeScanning.getClient(
                BarcodeScannerOptions.Builder()
                    .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                    .build()
            )

            val analysisUseCase = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()

            analysisUseCase.setAnalyzer(executor) { imageProxy ->
                if (!scanningEnabled) {
                    imageProxy.close()
                    return@setAnalyzer
                }

                val mediaImage = imageProxy.image
                if (mediaImage != null) {
                    val image = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)

                    barcodeScanner.process(image)
                        .addOnSuccessListener { barcodes ->
                            for (barcode in barcodes) {
                                barcode.rawValue?.let { value ->
                                    if (scannedText != value) {
                                        Toast.makeText(context, "Scanned: $value", Toast.LENGTH_SHORT).show()
                                        scannedText = value
                                        scanningEnabled = false
                                    }
                                }
                            }
                        }
                        .addOnFailureListener {
                            Log.e("ShareScreen", "QrCode scanning failed", it)
                        }
                        .addOnCompleteListener {
                            imageProxy.close()
                        }
                } else {
                    imageProxy.close()
                }
            }

            val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

            try {
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(
                    context as LifecycleOwner,
                    cameraSelector,
                    preview,
                    analysisUseCase
                )
            } catch (e: Exception) {
                Log.e("ShareScreen", "Use case binding failed", e)
            }

            previewView
        })


        if (showErrorDialog) {
            LaunchedEffect(Unit) {
                withContext(Dispatchers.IO) {
                    OpenID4VPManager.sendErrorToVerifier(Constants.ERR_NO_MATCHING_VCs)
                }
            }

            ErrorOverlay {
                showErrorDialog = false
                scanningEnabled = true
                scannedText = null
            }
        }
    }
}

@Composable
fun ErrorOverlay(onDismiss: () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.White.copy(alpha = 0.95f))
            .clickable(enabled = false) {},
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier
                .padding(24.dp)
                .fillMaxWidth()
        ) {
            Text(
                text = stringResource(R.string.invalid_qr_code),
                style = MaterialTheme.typography.h5,
                color = Color.Red
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = stringResource(R.string.no_matching_credential_found_for_the_scanned_qr_code),
                style = MaterialTheme.typography.body1,
                textAlign = TextAlign.Center
            )
            Spacer(modifier = Modifier.height(24.dp))
            Button(onClick = onDismiss) {
                Text(stringResource(R.string.ok))
            }
        }
    }
}


suspend fun handleScannedText(
    urlEncodedAuthRequest: String,
    sharedViewModel: SharedViewModel,
    navController: NavController,
    showError: () -> Unit,
    disableScanning: () -> Unit
) {
    val gson = Gson()
    sharedViewModel.updateScannedQr(urlEncodedAuthRequest)

    try {
        val authorizationRequest = withContext(Dispatchers.IO) {
            OpenID4VPManager.authenticateVerifier(
                urlEncodedAuthRequest
            )
        }


        val downloadedVcs = sharedViewModel.downloadedVcs
        val authRequestJson: JsonObject = gson.toJsonTree(authorizationRequest).asJsonObject

        val matchingVcsResult = MatchingVcsHelper().getVcsMatchingAuthRequest(downloadedVcs, authRequestJson)

        sharedViewModel.storeMatchResult(matchingVcsResult)

        delay(100)

        val hasMatchingVCs = matchingVcsResult.matchingVCs.values.any { it.isNotEmpty() }

        if (hasMatchingVCs) {
            navController.navigate("matching_vcs")
        } else {
            Log.d("CameraScanner", "No matching credentials found")
            showError()
            disableScanning()
        }

    } catch (e: Exception) {
        Log.e("CameraScanner", "Library processing failed", e)
        showError()
        disableScanning()
    }
}






