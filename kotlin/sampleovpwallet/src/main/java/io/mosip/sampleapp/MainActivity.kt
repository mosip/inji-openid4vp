package io.mosip.sampleapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import io.mosip.sampleapp.utils.OpenID4VPManager

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        OpenID4VPManager.init("sample-app")
        setContent {
            MaterialTheme {
                MainApp()
            }
        }
    }
}
