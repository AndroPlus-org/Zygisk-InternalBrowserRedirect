package com.github.kr328.ibr

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabsIntent
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import com.github.kr328.ibr.adapters.AppListAdapter
import com.github.kr328.ibr.components.AppListComponent
import com.github.kr328.ibr.databinding.ActivityMainBinding
import com.github.kr328.ibr.model.AppListElement
import com.github.kr328.ibr.remote.RemoteConnection

class MainActivity : AppCompatActivity() {
    private lateinit var component: AppListComponent
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        component = AppListComponent(MainApplication.fromContext(this))

        component.commandChannel.registerReceiver(AppListComponent.COMMAND_SHOW_EXCEPTION) {_, exception: AppListComponent.ExceptionType? ->
            showException(exception)
        }

        binding.activityMainMainList.adapter = AppListAdapter(this) {
            startActivity(Intent(this, AppEditActivity::class.java).setData(Uri.parse("package://$it")))
        }
        binding.activityMainMainList.layoutManager = LinearLayoutManager(this)

        binding.activityMainMainSwipe.setOnRefreshListener {
            component.commandChannel.sendCommand(AppListComponent.COMMAND_REFRESH_ONLINE_RULES, true)
        }

        component.elements.observe(this, this::updateList)

        component.commandChannel.registerReceiver(AppListComponent.COMMAND_SHOW_REFRESHING) { _, show: Boolean? ->
            runOnUiThread {
                with(binding.activityMainMainSwipe) {
                    if (show != isRefreshing) {
                        isRefreshing = show ?: false
                    }
                }
            }
        }
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.activity_main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.activity_main_menu_new_rule_set ->
                component.commandChannel.sendCommand(AppListComponent.COMMAND_SHOW_ADD_RULE_SET, this)
            R.id.activity_main_menu_settings ->
                startActivity(Intent(this, SettingsActivity::class.java))
            R.id.activity_main_menu_help ->
                CustomTabsIntent.Builder().build().launchUrl(this, Uri.parse(Constants.HELP_URL))
            R.id.activity_main_menu_about ->
                startActivity(Intent(this, AboutActivity::class.java))
            else -> return super.onOptionsItemSelected(item)
        }

        return true
    }

    override fun onStart() {
        super.onStart()

        if (RemoteConnection.currentStatus() != RemoteConnection.RCStatus.RUNNING) {
            showServiceStatus()
            return
        }

        component.commandChannel.sendCommand(AppListComponent.COMMAND_REFRESH_ONLINE_RULES, false)
    }

    override fun onDestroy() {
        super.onDestroy()

        component.shutdown()
    }

    private fun updateList(newData: List<AppListElement>) {
        val adapter = binding.activityMainMainList.adapter as AppListAdapter
        val oldData = adapter.appListElement

        val result = DiffUtil.calculateDiff(object : DiffUtil.Callback() {
            override fun areItemsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean =
                    oldData[oldItemPosition].packageName == newData[newItemPosition].packageName

            override fun getOldListSize(): Int = oldData.size

            override fun getNewListSize(): Int = newData.size

            override fun areContentsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean =
                    oldData[oldItemPosition].equalsBase(newData[newItemPosition])
        })

        adapter.appListElement = newData
        result.dispatchUpdatesTo(adapter)
    }

    private fun showException(exception: AppListComponent.ExceptionType?) {
        when (exception) {
            AppListComponent.ExceptionType.QUERY_DATA_FAILURE ->
                Toast.makeText(this,
                        R.string.app_list_application_query_data_failure,
                        Toast.LENGTH_LONG).show()
            AppListComponent.ExceptionType.REFRESH_FAILURE ->
                Toast.makeText(this,
                        R.string.app_list_application_refresh_failure,
                        Toast.LENGTH_LONG).show()
            else -> {}
        }
    }

    private fun showServiceStatus() {
        val resId = when (RemoteConnection.currentStatus()) {
            RemoteConnection.RCStatus.RUNNING -> R.string.app_list_application_error_invalid_service_message_unknown
            RemoteConnection.RCStatus.RIRU_NOT_LOADED -> R.string.app_list_application_error_invalid_service_message_riru_not_load
            RemoteConnection.RCStatus.RIRU_NOT_CALL_SYSTEM_SERVER_FORKED -> R.string.app_list_application_error_invalid_service_message_not_call_fork
            RemoteConnection.RCStatus.INJECT_FAILURE -> R.string.app_list_application_error_invalid_service_message_inject_failure
            RemoteConnection.RCStatus.SERVICE_NOT_CREATED -> R.string.app_list_application_error_invalid_service_message_service_not_created
            RemoteConnection.RCStatus.UNABLE_TO_HANDLE_REQUEST -> R.string.app_list_application_error_invalid_service_message_service_unable_to_handle
            RemoteConnection.RCStatus.SYSTEM_BLOCK_IPC -> R.string.app_list_application_error_invalid_service_message_system_block_ipc
            RemoteConnection.RCStatus.SERVICE_VERSION_NOT_MATCHES -> R.string.app_list_application_error_invalid_service_message_service_version_not_matches
            RemoteConnection.RCStatus.UNKNOWN -> R.string.app_list_application_error_invalid_service_message_unknown
        }

        AlertDialog.Builder(this)
                .setTitle(R.string.app_list_application_error_invalid_service_title)
                .setMessage(getString(resId)
                        .split("\n").joinToString("\n", transform = String::trim))
                .setCancelable(false)
                .setPositiveButton(R.string.app_list_application_error_invalid_service_button_ok) { _, _ -> finish() }
                .show()
    }
}

