package com.github.kr328.ibr

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.github.kr328.ibr.components.AppEditComponent
import com.github.kr328.ibr.databinding.ActivityEditAppBinding

class AppEditActivity : AppCompatActivity() {
    private lateinit var component: AppEditComponent
    private lateinit var binding: ActivityEditAppBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityEditAppBinding.inflate(layoutInflater)
        setContentView(binding.root)

        component = AppEditComponent(MainApplication.fromContext(this),
                intent.data?.host ?: throw IllegalArgumentException())

        component.commandChannel.registerReceiver(AppEditComponent.COMMAND_SHOW_EXCEPTION) { _, exception: AppEditComponent.ExceptionType? ->
            showException(exception)
        }

        binding.activityEditAppDebugMode.setOnCheckChangedListener { _, checked ->
            component.commandChannel.sendCommand(AppEditComponent.COMMAND_SET_DEBUG_ENABLED, checked)
        }
        binding.activityEditAppOnlineEnable.setOnCheckChangedListener { _, checked ->
            component.commandChannel.sendCommand(AppEditComponent.COMMAND_SET_ONLINE_ENABLED, checked)
        }
        binding.activityEditAppLocalEnable.setOnCheckChangedListener { _, checked ->
            component.commandChannel.sendCommand(AppEditComponent.COMMAND_SET_LOCAL_ENABLED, checked)
        }

        component.onlineRuleSet.observe(this) {
            if (it != null) {
                binding.activityEditAppOnlineRoot.visibility = View.VISIBLE
                binding.activityEditAppOnlineTag.summary = it.tag
                binding.activityEditAppOnlineAuthor.summary = it.author
            }
        }

        component.onlineRuleCount.observe(this) {
            binding.activityEditAppOnlineViewRules.summary = getString(R.string.edit_app_application_online_rule_set_view_rules_summary, it)
        }

        component.localRuleCount.observe(this) {
            binding.activityEditAppLocalViewRules.summary = getString(R.string.edit_app_application_local_rule_set_view_rules_summary, it)
        }

        component.appDate.observe(this) {
            with(binding.activityEditAppAppInfo) {
                packageName = it.packageName
                name = it.name
                version = it.version
                icon = it.icon
            }

            binding.activityEditAppRoot.visibility = View.VISIBLE
        }

        component.commandChannel.registerReceiver(AppEditComponent.COMMAND_INITIAL_FEATURE_ENABLED) { _, e: AppEditComponent.FeatureEnabled? ->
            binding.activityEditAppDebugMode.checked = e?.debug ?: false
            binding.activityEditAppOnlineEnable.checked = e?.online ?: false
            binding.activityEditAppLocalEnable.checked = e?.local ?: false
        }

        binding.activityEditAppOnlineViewRules.setOnClickListener {
            startActivity(Intent(this, RuleViewerActivity::class.java)
                    .setData(Uri.parse("pkg://${component.packageName}"))
                    .putExtra("type", "online"))
        }

        binding.activityEditAppLocalViewRules.setOnClickListener {
            startActivity(Intent(this, RuleViewerActivity::class.java)
                    .setData(Uri.parse("pkg://${component.packageName}"))
                    .putExtra("type", "local"))
        }

        binding.activityEditAppOnlineRoot.visibility =
                if (component.onlineRuleSet.value == null)
                    View.GONE
                else
                    View.VISIBLE

        binding.activityEditAppRoot.visibility = View.INVISIBLE
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.activity_edit_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == R.id.activity_edit_remove_rule_set)
            component.commandChannel.sendCommand(AppEditComponent.COMMAND_REMOVE_LOCAL_RULE_SET)

        return super.onOptionsItemSelected(item)
    }

    override fun onDestroy() {
        super.onDestroy()

        component.shutdown()
    }

    private fun showException(exception: AppEditComponent.ExceptionType?) {
        when (exception) {
            AppEditComponent.ExceptionType.LOAD_APP_INFO_FAILURE -> {
                Toast.makeText(this,
                        R.string.edit_app_application_exception_load_app_info_failure,
                        Toast.LENGTH_LONG).show()
                finish()
            }
            AppEditComponent.ExceptionType.QUERY_DATA_FROM_SERVICE_FAILURE -> {
                Toast.makeText(this,
                        R.string.edit_app_application_exception_query_data_failure,
                        Toast.LENGTH_LONG).show()
            }
            AppEditComponent.ExceptionType.REFRESH_FAILURE -> {
                Toast.makeText(this,
                        R.string.edit_app_application_exception_refresh_failure,
                        Toast.LENGTH_LONG).show()
            }
            AppEditComponent.ExceptionType.PUSH_DATA_TO_SERVICE_FAILURE -> {
                Toast.makeText(this,
                        R.string.edit_app_application_exception_push_data_to_service_failure,
                        Toast.LENGTH_LONG).show()
            }
            else -> {}
        }
    }
}
