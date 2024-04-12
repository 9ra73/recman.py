# recman.py

> Recording Manager for mirakc

## 使い方

大抵の場合、システムにインストールされている Python でそのまま実行できます:

```shell-session
$ ./recman.py -h
usage: recman.py [-h] [-k] [-n] [--watch] [--debug] ruleset

positional arguments:
  ruleset       ruleset.yml

options:
  -h, --help    show this help message and exit
  -k, --keep    keep untracked schedules
  -n, --dryrun  dry-run mode
  --watch       watch event stream
  --debug       enable debug logging
```

## 主な機能

このスクリプトには２つの動作モードがあります。

1. バッチ更新

    ルールセットと現在の EPG データに基づいて録画スケジュールを更新します。`--keep` オプションが指定されていない場合、未追跡のスケジュールは削除されます。

2. イベント監視

    mirakc のイベントストリームを監視し、ルールセットに基づいて録画スケジュールを更新します。`--keep` を含め、その他オプションも同様に機能します。

ルールセットファイルは以下のように動的コード生成を伴って解釈されます。

```yaml
- services: [400211] # BS11
  genres: [0x70, 0x71]
  genres!: [0x40, 0x52]
  tags: [archive]
  into: anime_2024spring
  priority: 10

# ...
```

↓

```python
def ruleset(sid, name, genres):
    if sid in {400211} and genres & {112, 113} and (not genres & {64, 82}):
        return rules[0]

    # ...
```

### 指定できる条件

- `services`: いずれかのサービスに一致 (list[int])
- `genres`: いずれかのジャンルに一致 (list[int])
- `prefix`: 前方一致 (str or list[str])
- `suffix`: 後方一致 (str or list[str])
- `name`: 部分一致 (str or list[str])
- `fuzz`: あいまい一致 (str or list[str])
- `fuzz_ratio`: あいまい一致のしきい値 (int, default: 90)

また、これらには否定条件のバリアントがあります。

- `services!`: いずれのサービスにも一致しない (list[int])
- `genres!`: いずれのジャンルにも一致しない (list[int])
- `prefix!`: 前方一致の否定 (str or list[str])
- `suffix!`: 後方一致の否定 (str or list[str])
- `name!`: 部分一致の否定 (str or list[str])
- `fuzz!`: あいまい一致の否定 (str or list[str])

### スケジュールに適用される項目

- `tags`: 録画スケジュールのタグ (list[str])
- `into`: 録画ファイルの保存先 (str. ディレクトリ名のみ)
- `priority`: 録画の優先度 (int, default: 1)

### その他

- `exclude`: 条件にマッチした番組を除外します (bool, default: false)
- `disabled`: ルールを単に無視します (bool, default: false)

## 依存関係

以下のライブラリに依存しています:

- `PyYAML`

あいまい一致を使う場合は以下のライブラリが別途必要です:

- `fuzzywuzzy`

## ライセンス

このプロジェクトは MIT ライセンスの下で公開されています。
