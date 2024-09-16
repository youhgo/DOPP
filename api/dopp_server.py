from flask import Flask


def create_app():
    """
    Function to create FLask API app
    :return: FLask app
    :rtype: FLask app
    """

    app = Flask(__name__)
    from api_views import dopp_api
    from api_parse import parse_api

    app.register_blueprint(dopp_api, url_prefix='/')
    app.register_blueprint(parse_api, url_prefix='/api/parse')
    app.config['CELERY_BROKER_URL'] = 'redis://redis:6379/0'
    app.config['CELERY_RESULT_BACKEND'] = 'redis://redis:6379/0'
    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8880)

    # curl -X POST https://DOPP.localhost/api/parse/parse_archive -F upload=/home/hro/Documents/working_zone/archive_orc/DFIR-ORC_WorkStation_DESKTOP-9I162HO1.7z -F data='{"caseName":"test"}'