"""Authenticated migration UI using the fixed root backup socket API."""
from flask import jsonify, redirect, render_template, request
from backup_routes import helper


def register(app, authorized, csrf):
    @app.get('/control/migration')
    def migration_home():
        if not authorized():return redirect('/control/')
        return render_template('migration.html', csrf=csrf())

    @app.get('/control/api/migration/state')
    def migration_status():
        try:return jsonify(helper({'op':'migration_status'}))
        except (OSError,ValueError):return jsonify(error='Служба переноса недоступна.'),503

    @app.post('/control/api/migration/action')
    def migration_action():
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or data.get('op') not in ('stop','resume'):
            return jsonify(error='Неизвестная операция.'),400
        try:return jsonify(helper({'op':'migration_'+data['op'],'confirm':data.get('confirm','')}))
        except (OSError,ValueError) as error:return jsonify(error=str(error)),400
